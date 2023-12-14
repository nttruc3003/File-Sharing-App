package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobPhone *client.User
	var bobLaptop *client.User

	var dorisPhone *client.User
	var dorisLaptop *client.User

	var frankPhone *client.User
	var frankLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	deepCopy := func(mp map[uuid.UUID][]byte) map[uuid.UUID][]byte {
		copyMap := make(map[uuid.UUID][]byte)
		for key, val := range mp {
			copyMap[key] = val
		}
		return copyMap
	}

	mapDifference := func(mp1 map[uuid.UUID][]byte, mp2 map[uuid.UUID][]byte) map[uuid.UUID][]byte {
		diff := make(map[uuid.UUID][]byte)
		for key, val := range mp2 {
			_, ok := mp1[key]
			if !ok {
				diff[key] = val
			}
		}
		return diff
	}

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Test InitUser Error.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("Basic Test: Test GetUser Error.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Bob.")
			_, err = client.GetUser("bob", defaultPassword)
			userlib.DebugMsg(err.Error())
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Get user Alice.")
			_, err = client.GetUser("alice", "truc")
			Expect(err).ToNot(BeNil())

		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Testing Revoke, and then invite again", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice append to file")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

		})
		Specify("Student Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie, Doris.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Bob accepting invite under name %s.", aliceFile, dorisFile)

			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Doris appending to file %s, content: %s", dorisFile, contentTwo)
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

	})

	Describe("Student Tests", func() {
		Specify("Student Test: Revoke Error ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob.")

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

		})

		Specify("Student test: Filename is not leaked", func() {
			userlib.DebugMsg("Initializing users Alice,")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice store empty file.")
			randomString := string(userlib.RandomBytes(1000))
			err = alice.StoreFile(randomString, []byte(""))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile(randomString)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))

			userlib.DebugMsg("Alice store empty filename.")
			err = alice.StoreFile("", []byte(""))
			Expect(err).To(BeNil())

		})

		Specify("Student Test: A invites B, B is revoked before accepting the invitation. ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob.")

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invitation")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can't still load the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			// Expect(data).ToNot(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can't append to the file")
			err = bob.AppendToFile(bobFile, []byte("abc"))
			Expect(err).ToNot(BeNil())
		})

		Specify("Student Test: A invites B, B accepts invitation, B invites C, B is revoked, C accepts invitation ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Frank.")

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invitation for Charles for file %s, and Bob accepting invite under name %s.", bobFile, charlesFile)
			invite2, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob is revoked.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite2, charlesFile)
			Expect(err).ToNot(BeNil())
		})
		Specify("Student Test: A invites B, C. B is revoked, C accepts invitation. C is revoked. C attempt to invite F. ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charles, and Frank.")

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())


			userlib.DebugMsg("Alice creating invitation for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob is revoked.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob can not accept invitation.")
			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles still can accept invitation.")
			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles is revoked.")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creating invitation for Frank for file %s", charlesFile)
			_, err = charles.CreateInvitation(charlesFile, "frank")
			Expect(err).ToNot(BeNil())


		})

	})

	Describe("Tampered Datastore", func() {
		Specify("Username Init and tampered datastore.", func() {

			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			mp := userlib.DatastoreGetMap()
			for key, _ := range mp {
				userlib.DatastoreDelete(key)
			}

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("creating file, and maliciously deleting file.", func() {
			userlib.DebugMsg("Initializing users Alice, and Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			before := deepCopy(userlib.DatastoreGetMap())
			// userlib.DebugMsg(strconv.Itoa(len(before)))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			after := deepCopy(userlib.DatastoreGetMap())

			var inv1 uuid.UUID
			inv1, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", inv1, bobFile)
			Expect(err).To(BeNil())

			// userlib.DebugMsg(strconv.Itoa(len(after)))

			diff := mapDifference(before, after)
			// userlib.DebugMsg(strconv.Itoa(len(diff)))
			for key, _ := range diff {
				userlib.DatastoreDelete(key)
			}

			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(Equal([]byte("")))

			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(Equal([]byte("")))

			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

		})

		Specify("Tampered Invitation", func() {
			userlib.DebugMsg("Initializing users Alice, and Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			before := deepCopy(userlib.DatastoreGetMap())
			var inv1 uuid.UUID
			inv1, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			after := deepCopy(userlib.DatastoreGetMap())
			diff := mapDifference(before, after)
			for key, _ := range diff {
				userlib.DatastoreGetMap()[key] = nil
			}

			err = bob.AcceptInvitation("alice", inv1, bobFile)
			Expect(err).ToNot(BeNil())

			data, err1 := alice.LoadFile(aliceFile)
			Expect(err1).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err1 = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err1).To(BeNil())

			err1 = bob.AppendToFile(bobFile, []byte(contentOne))
			Expect(err1).ToNot(BeNil())
		})

		Specify("Tampered Datastore, Revoke Accesss ", func() {
			userlib.DebugMsg("Initializing users Alice, and Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			before := deepCopy(userlib.DatastoreGetMap())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			after := deepCopy(userlib.DatastoreGetMap())

			var inv1 uuid.UUID
			inv1, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", inv1, bobFile)
			Expect(err).To(BeNil())
			diff := mapDifference(before, after)

			for key, _ := range diff {
				userlib.DatastoreDelete(key)
			}

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(Equal([]byte("")))

			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(Equal([]byte("")))

			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

		})

	})
	Describe("Student Tests: Invitation Test", func() {
		Specify("A invites B, but C accept. ", func() {
			userlib.DebugMsg("Initializing users A, B, C.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob for file %s, but Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob thinks invitation from Charles and try to accept invitation.")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

	})

	Describe("Student Tests: Big Invitation Test", func() {
		Specify("A invites B, C. B invites D, E. C invites F, G. G invites H, I. A revokes C. ", func() {
			userlib.DebugMsg("Initializing users A, B, C, D ,E ,F , G, H, I.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())

			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob and Charles for file %s, and Bob , Charles accepting invite under name %s, %s.", aliceFile, bobFile, charlesFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invitation for Doris and Frank for file %s, and Doris , Frank accepting invite under name %s, %s.", bobFile, dorisFile, frankFile)
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			invite, err = bob.CreateInvitation(bobFile, "frank")
			Expect(err).To(BeNil())

			err = frank.AcceptInvitation("bob", invite, frankFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Frank can load the file.")
			data, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Charles creating invitation for Eve and Grace for file %s, and Eve, Grace accepting invite under name %s, %s.", charlesFile, eveFile, graceFile)
			invite, err = charles.CreateInvitation(charlesFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("charles", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Eve can load the file.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			invite, err = charles.CreateInvitation(charlesFile, "grace")
			Expect(err).To(BeNil())

			err = grace.AcceptInvitation("charles", invite, graceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Grace can load the file.")
			data, err = grace.LoadFile(graceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Grace creating invitation for Horace and Ira for file %s, and Horace, Ira accepting invite under name %s, %s.", graceFile, horaceFile, iraFile)
			invite, err = grace.CreateInvitation(graceFile, "horace")
			Expect(err).To(BeNil())

			err = horace.AcceptInvitation("grace", invite, horaceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Horace can load the file.")
			data, err = horace.LoadFile(horaceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			invite, err = grace.CreateInvitation(graceFile, "ira")
			Expect(err).To(BeNil())

			err = ira.AcceptInvitation("grace", invite, iraFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Ira can load the file.")
			data, err = ira.LoadFile(iraFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Charles's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles, Eve, Grace, Horace, and Ira lost access to the file.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())

			_, err = grace.LoadFile(graceFile)
			Expect(err).ToNot(BeNil())

			_, err = horace.LoadFile(horaceFile)
			Expect(err).ToNot(BeNil())

			_, err = ira.LoadFile(iraFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = eve.AppendToFile(eveFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = grace.AppendToFile(graceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = horace.AppendToFile(horaceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = ira.AppendToFile(iraFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the other users can append to the file.")

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentOne)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris appending to file %s, content: %s", dorisFile, contentTwo)
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Frank appending to file %s, content: %s", dorisFile, contentThree)
			err = frank.AppendToFile(frankFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that the other users can load to the file and see the new content.")

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that the other intances of available users can append file")

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Bob - bobLaptop")
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Doris - dorisLaptop")
			dorisLaptop, err = client.GetUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Frank - frankLaptop")
			frankLaptop, err = client.GetUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - alicePhone")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Bob - bobPhone")
			bobPhone, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Doris - dorisPhone")
			dorisPhone, err = client.GetUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Frank - frankPhone")
			frankPhone, err = client.GetUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone appending to file %s, content: %s", aliceFile, contentThree)
			err = alicePhone.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bobPhone appending to file %s, content: %s", aliceFile, contentThree)
			err = bobPhone.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("dorisPhone appending to file %s, content: %s", aliceFile, contentThree)
			err = dorisPhone.AppendToFile(dorisFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("frankPhone appending to file %s, content: %s", aliceFile, contentThree)
			err = frankPhone.AppendToFile(frankFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that the other intances of available users can load file")

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree + contentThree + contentThree + contentThree + contentThree)))

			userlib.DebugMsg("Checking that bobLaptop sees expected file data.")
			data, err = bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree + contentThree + contentThree + contentThree + contentThree)))

			userlib.DebugMsg("Checking that dorisLaptop sees expected file data.")
			data, err = dorisLaptop.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree + contentThree + contentThree + contentThree + contentThree)))

			userlib.DebugMsg("Checking that frankLaptop sees expected file data.")
			data, err = frankLaptop.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentOne + contentTwo + contentTwo + contentThree + contentThree + contentThree + contentThree + contentThree)))

		})

	})
	Describe("Student Tests: Invitation Test", func() {
		Specify("A invites B, but C accept. ", func() {
			userlib.DebugMsg("Initializing users A, B, C.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob for file %s, but Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob thinks invitation from Charles and try to accept invitation.")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

	})
	Describe("Student Tests: Data tamper.", func() {
		Specify("Tamper the data through out the process.", func() {

			userlib.DebugMsg("Initializing users A, B, C.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			before := deepCopy(userlib.DatastoreGetMap())
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			after := deepCopy(userlib.DatastoreGetMap())

			newData := newUUIDmap(before, after)
			userlib.DebugMsg("Attacker tamper the file, and Alice load it")
			errCount := 0
			for k, v := range newData {
				userlib.DatastoreSet(k, userlib.RandomBytes(64))
				_, err := alice.LoadFile(aliceFile)
				if err != nil {
					errCount++
				}
				restoreCorruptedUUID(k, v)
			}
			Expect(errCount == 0).To(BeFalse())

			before = deepCopy(userlib.DatastoreGetMap())
			userlib.DebugMsg("Alice creating invitation for Bob for file %s.", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			after = deepCopy(userlib.DatastoreGetMap())
			//get the newUUID on the datastore which corresponding to new invitation
			newData = newUUIDmap(before, after)
			userlib.DebugMsg("Attacker tamper the invitation.")
			errCount = 0
			for k, v := range newData {

				userlib.DatastoreSet(k, userlib.RandomBytes(64))
				err = bob.AcceptInvitation("alice", invite, bobFile)
				if err != nil {
					errCount++
				}
				restoreCorruptedUUID(k, v)
			}
			Expect(errCount == 0).To(BeFalse())

		})
	})

})

//clear the dataStore and upload the original map to Datastore
func restoreDataStore(originalDatastore map[uuid.UUID][]byte) {
	userlib.DatastoreClear()
	for k, v := range originalDatastore {
		userlib.DatastoreSet(k, v)
	}
}

//restore the corrupted UUID by original data
func restoreCorruptedUUID(corrUUID uuid.UUID, originalData []byte) {
	if corrUUID != uuid.Nil {
		userlib.DatastoreSet(corrUUID, originalData)
	}
}

//get the map of new UUID and Data
func newUUIDmap(beforeMap map[uuid.UUID][]byte, afterMap map[uuid.UUID][]byte) map[uuid.UUID][]byte {
	newDataMap := make(map[uuid.UUID][]byte)
	for k, v := range afterMap {

		_, exist := beforeMap[k]
		if !exist {

			// userlib.DebugMsg("after: %v -> %v", k , v)
			newDataMap[k] = v

		}

	}
	// userlib.DebugMsg("newDataMap. %v", newDataMap)
	return newDataMap
}
