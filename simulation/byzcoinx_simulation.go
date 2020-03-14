package simulation

/*
The simulation-file can be used with the `cothority/simul` and be run either
locally or on deterlab. Contrary to the `test` of the protocol, the simulation
is much more realistic, as it tests the protocol on different nodes, and not
only in a test-environment.
The Setup-method is run once on the client and will create all structures
and slices necessary to the simulation. It also receives a 'dir' argument
of a directory where it can write files. These files will be copied over to
the simulation so that they are available.
The Run-method is called only once by the root-node of the tree defined in
Setup. It should run the simulation in different rounds. It can also
measure the time each run takes.
In the Node-method you can read the files that have been created by the
'Setup'-method.
*/

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/csanti/byzcoin-experiments/byzcoinx"
	"go.dedis.ch/cothority/blscosi/bdnproto"
	"go.dedis.ch/cothority/blscosi/protocol"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/pairing"
	"go.dedis.ch/onet"
	"go.dedis.ch/onet/log"
	"go.dedis.ch/onet/simul/monitor"
)

// Name of the simulation
var Name = "byzcoinx"

func init() {
	log.Lvl1("init simulation")
	onet.SimulationRegister(Name, NewSimulationProtocol)
	// register the protools that we will use in the Simulation
	err := byzcoinx.GlobalInitBdnCoSiProtocol(testSuite, verify, ack, "TestBDN")
	if err != nil {
		panic(err)
	}
}

// SimulationProtocol implements onet.Simulation.
type SimulationProtocol struct {
	onet.SimulationBFTree
}

// NewSimulationProtocol is used internally to register the simulation (see the init()
// function above).
func NewSimulationProtocol(config string) (onet.Simulation, error) {
	es := &SimulationProtocol{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup implements onet.Simulation.
func (s *SimulationProtocol) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	s.CreateTree(sc)

	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationProtocol) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

// Run implements onet.Simulation.
func (s *SimulationProtocol) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)
	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		round := monitor.NewTimeMeasure("round")
		pi, err := config.Overlay.CreateProtocol("TestBDN", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		publics := config.Roster.Publics()
		bftCosiProto := pi.(*byzcoinx.ByzCoinX)

		bftCosiProto.CreateProtocol = func(name string, t *onet.Tree) (onet.ProtocolInstance, error) {
			return config.Overlay.CreateProtocol(name, t, onet.NilServiceID)
		}
		bftCosiProto.FinalSignatureChan = make(chan byzcoinx.FinalSignature, 1)

		counter := &Counter{refuseIndex: 0}
		counters.add(counter)

		proposal := []byte(strconv.Itoa(counters.size() - 1))
		bftCosiProto.Msg = proposal
		bftCosiProto.Data = []byte("hello world")
		bftCosiProto.Timeout = defaultTimeout
		bftCosiProto.Threshold = s.Hosts - 1
		log.Lvl3("Added counter", counters.size()-1, 0)

		err = bftCosiProto.Start()
		if err != nil {
			return err
		}

		var sig byzcoinx.FinalSignature
		timeout := defaultTimeout + time.Second
		select {
		case sig = <-bftCosiProto.FinalSignatureChan:
		case <-time.After(timeout):
			return fmt.Errorf("didn't get commitment after a timeout of %v", timeout)
		}
		round.Record()

		err = getAndVerifySignature(sig, publics, proposal, 1)
		if err != nil {
			return err
		}

		counter.Lock()
		defer counter.Unlock()

		log.Lvl1(" ---------------------------")
		log.Lvl1("End of round => Counter: ", counter.veriCount)
		log.Lvl1(" ---------------------------")
	}

	return nil
}

var defaultTimeout = 20 * time.Second
var testSuite = pairing.NewSuiteBn256()

type Counter struct {
	veriCount   int
	refuseIndex int
	sync.Mutex
}

type Counters struct {
	counters []*Counter
	sync.Mutex
}

func (co *Counters) add(c *Counter) {
	co.Lock()
	co.counters = append(co.counters, c)
	co.Unlock()
}

func (co *Counters) size() int {
	co.Lock()
	defer co.Unlock()
	return len(co.counters)
}

func (co *Counters) get(i int) *Counter {
	co.Lock()
	defer co.Unlock()
	return co.counters[i]
}

var counters = &Counters{}

// verify function that returns true if the length of the data is 1.
func verify(msg, data []byte) bool {
	c, err := strconv.Atoi(string(msg))
	if err != nil {
		log.Error("Failed to cast msg", msg)
		return false
	}

	if len(data) == 0 {
		log.Error("Data is empty.")
		return false
	}

	counter := counters.get(c)
	counter.Lock()
	counter.veriCount++
	log.Lvl4("Verification called", counter.veriCount, "times")
	counter.Unlock()
	if len(msg) == 0 {
		log.Error("Didn't receive correct data")
		return false
	}
	return true
}

// verifyRefuse will refuse the refuseIndex'th calls
func verifyRefuse(msg, data []byte) bool {
	c, err := strconv.Atoi(string(msg))
	if err != nil {
		log.Error("Failed to cast", msg)
		return false
	}

	counter := counters.get(c)
	counter.Lock()
	defer counter.Unlock()
	defer func() { counter.veriCount++ }()
	if counter.veriCount == counter.refuseIndex {
		log.Lvl2("Refusing for count==", counter.refuseIndex)
		return false
	}
	log.Lvl3("Verification called", counter.veriCount, "times")
	if len(msg) == 0 {
		log.Error("Didn't receive correct data")
		return false
	}
	return true
}

// ack is a dummy
func ack(a, b []byte) bool {
	return true
}

func getAndVerifySignature(sig byzcoinx.FinalSignature, publics []kyber.Point, proposal []byte, scheme int) error {

	// verify signature
	if sig.Sig == nil {
		return fmt.Errorf("signature is nil")
	}
	if !bytes.Equal(sig.Msg, proposal) {
		return fmt.Errorf("message in the signature is different from proposal")
	}
	err := func() error {
		switch scheme {
		case 1:
			return bdnproto.BdnSignature(sig.Sig).Verify(testSuite, proposal, publics)
		default:
			return protocol.BlsSignature(sig.Sig).Verify(testSuite, proposal, publics)
		}
	}()
	if err != nil {
		return fmt.Errorf("didn't get a valid signature: %s", err)
	}
	log.Lvl2("Signature correctly verified!")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
