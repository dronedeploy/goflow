package goflow

import (
	"errors"
	"testing"
)

func newRepeatGraph() (*Graph, error) {
	n := NewGraph()

	if err := n.Add("r", new(repeater)); err != nil {
		return nil, err
	}

	n.MapInPort("Word", "r", "Word")
	n.MapOutPort("Words", "r", "Words")

	return n, nil
}

func TestStructIIP(t *testing.T) {
	g := NewGraph()
	e := &echoMyStruct{}
	if err := g.Add("e", e); err != nil {
		t.Fatal(err)
	}
	g.MapInPort("In", "e", "In")
	g.MapOutPort("Out", "e", "Out")

	out := make(chan *myStruct)
	g.SetOutPort("Out", out)

	dat := &myStruct{
		A: "hello",
		B: "world",
	}
	if err := g.AddIIP("e", "In", dat); err != nil {
		t.Fatal(err)
	}

	wait := Run(g)
	var ok bool
do_loop:
	for {
		select {
		case <-wait:
			break do_loop
		case <-out:
			ok = true
		}
	}

	if !ok {
		t.Fatal(errors.New("no output"))
	}
}

func TestMapStructIIP(t *testing.T) {
	g := NewGraph()
	e := &echoMyStruct{}
	if err := g.Add("e", e); err != nil {
		t.Fatal(err)
	}
	g.MapInPort("In", "e", "In")
	g.MapOutPort("Out", "e", "Out")

	out := make(chan *myStruct)
	g.SetOutPort("Out", out)

	dat := &map[string]interface{}{
		"a": "hello",
		"b": "world",
	}
	if err := g.AddIIP("e", "In", dat); err != nil {
		t.Fatal(err)
	}

	wait := Run(g)
	var ok bool
do_loop:
	for {
		select {
		case <-wait:
			break do_loop
		case <-out:
			ok = true
		}
	}

	if !ok {
		t.Fatal(errors.New("no output"))
	}
}

func TestMapEmptyStructIIP1(t *testing.T) {
	g := NewGraph()
	e := &echoEmptyStruct{}
	if err := g.Add("e", e); err != nil {
		t.Fatal(err)
	}
	g.MapInPort("In", "e", "In")
	g.MapOutPort("Out", "e", "Out")

	out := make(chan struct{})
	g.SetOutPort("Out", out)

	dat := &map[string]interface{}{}
	if err := g.AddIIP("e", "In", dat); err != nil {
		t.Fatal(err)
	}

	wait := Run(g)
	var ok bool
do_loop:
	for {
		select {
		case <-wait:
			break do_loop
		case <-out:
			ok = true
		}
	}

	if !ok {
		t.Fatal(errors.New("no output"))
	}
}

func TestMapEmptyStructIIP2(t *testing.T) {
	g := NewGraph()
	e := &echoEmptyStruct{}
	if err := g.Add("e", e); err != nil {
		t.Fatal(err)
	}
	g.MapInPort("In", "e", "In")
	g.MapOutPort("Out", "e", "Out")

	out := make(chan struct{})
	g.SetOutPort("Out", out)

	if err := g.AddIIP("e", "In", struct{}{}); err != nil {
		t.Fatal(err)
	}

	wait := Run(g)
	var ok bool
do_loop:
	for {
		select {
		case <-wait:
			break do_loop
		case <-out:
			ok = true
		}
	}

	if !ok {
		t.Fatal(errors.New("no output"))
	}
}

func TestBasicIIP(t *testing.T) {
	qty := 5

	n, err := newRepeatGraph()
	if err != nil {
		t.Error(err)
		return
	}
	if err := n.AddIIP("r", "Times", qty); err != nil {
		t.Error(err)
		return
	}

	input := "hello"
	output := []string{"hello", "hello", "hello", "hello", "hello"}

	in := make(chan string)
	out := make(chan string)

	if err := n.SetInPort("Word", in); err != nil {
		t.Error(err)
		return
	}
	if err := n.SetOutPort("Words", out); err != nil {
		t.Error(err)
		return
	}

	wait := Run(n)

	go func() {
		in <- input
		close(in)
	}()

	i := 0
	for actual := range out {
		expected := output[i]
		if actual != expected {
			t.Errorf("%s != %s", actual, expected)
		}
		i++
	}
	if i != qty {
		t.Errorf("Returned %d words instead of %d", i, qty)
	}

	<-wait
}

func newRepeatGraph2Ins() (*Graph, error) {
	n := NewGraph()

	if err := n.Add("r", new(repeater)); err != nil {
		return nil, err
	}

	n.MapInPort("Word", "r", "Word")
	n.MapInPort("Times", "r", "Times")
	n.MapOutPort("Words", "r", "Words")

	return n, nil
}

func TestGraphInportIIP(t *testing.T) {
	qty := 5

	n, err := newRepeatGraph2Ins()
	if err != nil {
		t.Error(err)
		return
	}

	input := "hello"
	output := []string{"hello", "hello", "hello", "hello", "hello"}

	in := make(chan string)
	times := make(chan int)
	out := make(chan string)

	if err := n.SetInPort("Word", in); err != nil {
		t.Error(err)
		return
	}
	if err := n.SetInPort("Times", times); err != nil {
		t.Error(err)
		return
	}
	if err := n.SetOutPort("Words", out); err != nil {
		t.Error(err)
		return
	}
	if err := n.AddIIP("r", "Times", qty); err != nil {
		t.Error(err)
		return
	}

	wait := Run(n)

	go func() {
		in <- input
		close(in)
	}()

	i := 0
	for actual := range out {
		if i == 0 {
			// The graph inport needs to be closed once the IIP is sent
			close(times)
		}
		expected := output[i]
		if actual != expected {
			t.Errorf("%s != %s", actual, expected)
		}
		i++
	}
	if i != qty {
		t.Errorf("Returned %d words instead of %d", i, qty)
	}

	<-wait
}

func TestInternalConnectionIIP(t *testing.T) {
	input := 1
	iip := 2
	output := []int{1, 2}
	qty := 2

	n, err := newDoubleEcho()
	if err != nil {
		t.Error(err)
		return
	}

	if err := n.AddIIP("e2", "In", iip); err != nil {
		t.Error(err)
		return
	}

	in := make(chan int)
	out := make(chan int)

	if err := n.SetInPort("In", in); err != nil {
		t.Error(err)
		return
	}
	if err := n.SetOutPort("Out", out); err != nil {
		t.Error(err)
		return
	}

	wait := Run(n)

	go func() {
		in <- input
		close(in)
	}()

	i := 0
	for actual := range out {
		// The order of output is not guaranteed in this case
		if actual != output[0] && actual != output[1] {
			t.Errorf("Unexpected value %d", actual)
		}
		i++
	}
	if i != qty {
		t.Errorf("Returned %d words instead of %d", i, qty)
	}

	<-wait
}

func TestAddRemoveIIP(t *testing.T) {
	n := NewGraph()

	if err := n.Add("e", new(echo)); err != nil {
		t.Error(err)
		return
	}

	if err := n.AddIIP("e", "In", 5); err != nil {
		t.Error(err)
		return
	}

	// Adding an IIP to a non-existing process/port should fail
	if err := n.AddIIP("d", "No", 404); err == nil {
		t.FailNow()
		return
	}

	if err := n.RemoveIIP("e", "In"); err != nil {
		t.Error(err)
		return
	}

	// Second attempt to remove same IIP should fail
	if err := n.RemoveIIP("e", "In"); err == nil {
		t.FailNow()
		return
	}
}
