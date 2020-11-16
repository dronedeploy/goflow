package goflow

import (
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

var structType = reflect.TypeOf(struct{}{})

// iip stands for Initial Information Packet representation
// within the network.
type iip struct {
	data interface{}
	addr address
}

// AddIIP adds an Initial Information packet to the network
func (n *Graph) AddIIP(processName, portName string, data interface{}) error {
	addr := parseAddress(processName, portName)
	if _, exists := n.procs[processName]; exists {
		n.iips = append(n.iips, iip{data: data, addr: addr})
		return nil
	}
	return fmt.Errorf("AddIIP: could not find '%s'", addr)
}

// RemoveIIP detaches an IIP from specific process and port
func (n *Graph) RemoveIIP(processName, portName string) error {
	addr := parseAddress(processName, portName)
	for i := range n.iips {
		if n.iips[i].addr == addr {
			// Remove item from the slice
			n.iips[len(n.iips)-1], n.iips[i], n.iips = iip{}, n.iips[len(n.iips)-1], n.iips[:len(n.iips)-1]
			return nil
		}
	}
	return fmt.Errorf("RemoveIIP: could not find IIP for '%s'", addr)
}

// sendIIPs sends Initial Information Packets upon network start
func (n *Graph) sendIIPs() error {
	// Send initial IPs
	for i := range n.iips {
		ip := n.iips[i]
		// Get the receiver port channel
		var channel reflect.Value
		found := false
		shouldClose := false

		// Try to find it among network inports
		for j := range n.inPorts {
			if n.inPorts[j].addr == ip.addr {
				channel = n.inPorts[j].channel
				if !channel.IsValid() {
					continue
				}
				found = true
				break
			}
		}

		if !found {
			// Try to find among connections
			for j := range n.connections {
				if n.connections[j].tgt == ip.addr {
					channel = n.connections[j].channel
					if !channel.IsValid() {
						continue
					}
					found = true
					break
				}
			}
		}

		if !found {
			// Try to find a proc and attach a new channel to it
			recvPort, recvIndex, recvKey, err := n.getProcPort(ip.addr.proc, ip.addr.port, reflect.RecvDir)
			if err != nil {
				return err
			}

			if recvIndex > -1 {
				channel, err = attachArrayPort(recvPort, recvIndex, reflect.RecvDir, reflect.ValueOf(nil), n.conf.BufferSize)
			} else if recvKey != "" {
				channel, err = attachMapPort(recvPort, recvKey, reflect.RecvDir, reflect.ValueOf(nil), n.conf.BufferSize)
			} else {
				channel, err = attachPort(recvPort, ip.addr, reflect.RecvDir, reflect.ValueOf(nil), n.conf.BufferSize)
			}
			if err != nil {
				return err
			}

			found = true
			shouldClose = true
		}

		if found {
			// Make sure the channel is valid.
			if !channel.IsValid() {
				return fmt.Errorf("port lookup for %v returned invalid channel", ip.addr)
			}

			// Check if the IIP data is going to be the right type.
			dat := ip.data
			targetType := channel.Type().Elem()
			t := reflect.TypeOf(ip.data)
			if !t.AssignableTo(targetType) {

				// The thing we received wasn't _exactly_ the right type, but see if we can intelligently convert it using mapstructure.

				if t == structType {
					// If the expected type is a struct, then it doesn't really matter what the input data is, so accept anything.
					dat = struct{}{}
				} else {
					// Else, try to convert using mapstructure.
					dp := reflect.New(targetType)
					di := dp.Interface()
					if err := mapstructure.Decode(ip.data, di); err != nil {
						// If map structure fails, we're out of ideas.
						if shouldClose {
							channel.Close()
						}
						return fmt.Errorf("can't send IIP: %v cannot fit into %v", reflect.TypeOf(ip.data), channel.Type())
					}
					dp = reflect.ValueOf(di)
					dat = dp.Elem().Interface()
				}
			}

			// Send data to the port
			go func() {
				channel.Send(reflect.ValueOf(dat))
				if shouldClose {
					channel.Close()
				}
			}()
		} else {
			return fmt.Errorf("IIP target not found: '%s'", ip.addr)
		}
	}
	return nil
}
