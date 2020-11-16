package goflow

import (
	"fmt"
	"reflect"
)

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
				found = true
				break
			}
		}

		if !found {
			// Try to find among connections
			for j := range n.connections {
				if n.connections[j].tgt == ip.addr {
					channel = n.connections[j].channel
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
			if channel.IsZero() {
				return fmt.Errorf("port lookup returned invalid channel")
			}

			// Check if the IIP data is going to be the right type.
			t := reflect.TypeOf(ip.data)
			if !t.AssignableTo(channel.Type().Elem()) {
				if shouldClose {
					channel.Close()
				}

				return fmt.Errorf("can't send IIP: %v cannot fit into %v", reflect.TypeOf(ip.data), channel.Type())
			}

			// Send data to the port
			go func() {
				channel.Send(reflect.ValueOf(ip.data))
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
