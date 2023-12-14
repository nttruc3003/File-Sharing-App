package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

func compareBytes(byte1 []byte, byte2 []byte) bool {
	if len(byte1) != len(byte2) {
		return false
	}

	for i := range byte1 {
		if byte1[i] != byte2[i] {
			return false
		}
	}

	return true
}

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
const Length = 16

type User struct {
	Username     string
	PasswordHash []byte
	PrivateKey   userlib.PKEDecKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type UserMetadata struct {
	PasswordSalt      []byte
	HMACSalt          []byte
	EncryptUserStruct []byte
	HMACVal           []byte
}

type File struct {
	Last_Node uuid.UUID
}

type FileMetadata struct {
	SharingSalt        []byte
	HMACSalt           []byte
	FileSalt           []byte
	Encrypt_FileStruct []byte
}

type FileContent struct {
	Content      []byte
	PreviousNode uuid.UUID
}

type FileNode struct {
	Encrypt_FileContent []byte
	FileSalt            []byte
	HMACSalt            []byte
}

type Invitation struct {
	OwnnerUsername        string
	Sender                string
	Invitee               string
	UUIDFileMetadata      uuid.UUID
	EncryptedAccessingKey []byte
	EncryptedSharingKey   []byte
	Accepted              bool
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var exist bool
	_, exist = userlib.KeystoreGet(username)
	if exist {
		userlib.DebugMsg("Username already exists.")
		return nil, errors.New("Username already exists.")
	}

	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()

	HMACSalt := userlib.RandomBytes(Length)
	PasswordSalt := userlib.RandomBytes(Length)

	var userdata User
	userdata.Username = username
	userdata.PasswordHash = userlib.Argon2Key([]byte(password), PasswordSalt, Length)
	userdata.PrivateKey = sk

	hmacKey := userlib.Argon2Key([]byte(password), HMACSalt, Length)
	var metadata UserMetadata
	metadata.PasswordSalt = PasswordSalt
	metadata.HMACSalt = HMACSalt
	var serialized_user_struct []byte
	serialized_user_struct, _ = json.Marshal(userdata)
	metadata.EncryptUserStruct = userlib.SymEnc(userdata.PasswordHash[:16], userlib.RandomBytes(Length), serialized_user_struct)
	metadata.HMACVal, _ = userlib.HMACEval(hmacKey[:16], metadata.EncryptUserStruct)

	// Store public key
	userlib.KeystoreSet(username, pk)

	var uuidString string = "Users/" + username + "/usermetadata"

	var serialized_usermetadata_struct []byte
	serialized_usermetadata_struct, _ = json.Marshal(metadata)
	deterministicUUID := getUUIDFromString(uuidString)
	userlib.DatastoreSet(deterministicUUID, serialized_usermetadata_struct)

	return &userdata, nil
}

func getUUIDFromString(str string) (keyStore uuid.UUID) {
	serialized_str, _ := json.Marshal(str)
	hashValue := userlib.Hash(serialized_str)[:Length]
	deterministicUUID, _ := uuid.FromBytes(hashValue)
	return deterministicUUID
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var exist bool
	_, exist = userlib.KeystoreGet(username)
	if !exist {
		// userlib.DebugMsg("Username does not exist.")
		return nil, errors.New("Username does not exist.")
	}

	var userdata User
	var metadata UserMetadata
	var ok bool

	keyUUID := getUUIDFromString("Users/" + username + "/usermetadata")
	dataJSON, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		userlib.DebugMsg("Could not retreive data from DATASTORE.")
		return nil, errors.New("Could not retreive data from DATASTORE.")
	}
	json.Unmarshal(dataJSON, &metadata)

	passwordKey := userlib.Argon2Key([]byte(password), metadata.PasswordSalt, Length)
	hmacKey := userlib.Argon2Key([]byte(password), metadata.HMACSalt, Length)
	computedHMAC, _ := userlib.HMACEval(hmacKey[:16], metadata.EncryptUserStruct)
	if !userlib.HMACEqual(computedHMAC, metadata.HMACVal) {
		// userlib.DebugMsg("Datastore is tampered/W.")
		return nil, errors.New("Cound't log in.")
	}

	decryptJson := userlib.SymDec(passwordKey, metadata.EncryptUserStruct)

	e := json.Unmarshal(decryptJson, &userdata)
	if e != nil {
		userlib.DebugMsg("Could not marshall data.")
		return nil, e
	}

	if !compareBytes(userdata.PasswordHash, passwordKey) {
		userlib.DebugMsg("Wrong password.")
		return nil, errors.New("Wrong password.")

	}

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// Generate uuid from string
	metadata_UUID := getUUIDFromString(userdata.Username + "/" + filename + "/FileMetadataStruct")

	// check to make sure filename doesn't exist.
	_, ok := userlib.DatastoreGet(metadata_UUID)
	if ok {
		userlib.DebugMsg("Filename exists.")
		return errors.New("Filename exists.")
	}

	// Node uuid
	uuidNode := uuid.New()
	// userlib.DebugMsg(uuid.String())

	// Initilalize FileStruct
	var fileStruct File
	fileStruct.Last_Node = uuidNode
	sharingSalt := userlib.RandomBytes(Length)

	// generate sharingKey on a fly
	sharingKey := getKeyFromSourceKey(userdata.PasswordHash, sharingSalt)
	// sharingKey, _ := userlib.HashKDF(userdata.PasswordHash, sharingSalt)
	// sharingKey = sharingKey[:16]

	//fromTrucN: create invitation rootNode and upload to DataStore
	var invitationRoot Invitation
	invitationRoot.OwnnerUsername = userdata.Username
	invitationRoot.Sender = userdata.Username
	invitationRoot.Invitee = userdata.Username
	invitationRoot.UUIDFileMetadata = metadata_UUID
	invitationRoot.Accepted = true

	pk, ok := userlib.KeystoreGet(userdata.Username)

	iv := userlib.RandomBytes(16)
	accessingKey := userlib.RandomBytes(16)
	invitationRoot.EncryptedSharingKey = userlib.SymEnc(accessingKey, iv, sharingKey)
	invitationRoot.EncryptedAccessingKey, err = userlib.PKEEnc(pk, accessingKey)
	if err != nil {
		userlib.DebugMsg("Can not encrypt AccessingKey")
		return err
	}

	invitationUUID := uuid.New()
	// randSalt := userlib.RandomBytes(32)
	// invitationUUID := getUUIDFromString(string(randSalt))

	serialized_invitationRoot, _ := json.Marshal(invitationRoot)

	userlib.DatastoreSet(invitationUUID, serialized_invitationRoot)
	userdata.HMACUpload(invitationUUID, serialized_invitationRoot)

	//create a uuid invitations storage and upload the invitation uuid
	invitattionUUIDStorage := getUUIDFromString(userdata.Username + "/" + filename + "/Invitation")
	serialized_invitationUUID, _ := json.Marshal(invitationUUID)
	// userlib.DebugMsg("invitationUUID : %v", serialized_invitationUUID)
	userlib.DatastoreSet(invitattionUUIDStorage, serialized_invitationUUID)
	userdata.HMACUpload(invitattionUUIDStorage, serialized_invitationUUID)

	//create childrenList and upload to dataStore
	childrenListUUID := getUUIDFromString(invitationUUID.String() + "/ChildrenList")
	var childrenList []uuid.UUID
	serialized_childrenList, _ := json.Marshal(childrenList)
	userlib.DatastoreSet(childrenListUUID, serialized_childrenList)
	userdata.HMACUpload(childrenListUUID, serialized_childrenList)

	// testData, _ := userlib.DatastoreGet(invitationUUID)

	// userlib.DebugMsg("Check HMAC VAL for Invitation Root")
	// userdata.HMACDownload(invitationUUID, testData)
	// userlib.DebugMsg("Data nis not tampered")

	// //change file owner to Bob and upload to the same uuid and check HMAC download
	// userlib.DebugMsg("Change file owner to Bob anh check")
	// invitationRoot.OwnnerUsername = "bob"

	// newSerialized_invitationRoot, _ := json.Marshal(invitationRoot)
	// userlib.DatastoreSet(invitationUUID, newSerialized_invitationRoot)
	// // userdata.HMACUpload(invitationUUID, serialized_invitationRoot)
	// newTestData, _ := userlib.DatastoreGet(invitationUUID)
	// userdata.HMACDownload(invitationUUID, newTestData)

	// serialized_invitationUUID, _ := json.Marshal(invitationUUID)
	// userlib.DatastoreSet(invitattionUUIDStorage, serialized_invitationUUID)
	// userdata.HMACUpload(invitattionUUIDStorage, serialized_invitationUUID)
	// invChildrenUUID:= getUUIDFromString(invitationUUID.String() + "/InvitationChildren")

	//From TrucN : end

	// Generate fileContent struct
	noneUUID := getUUIDFromString("0")
	var fileContent FileContent
	fileContent.Content = content
	fileContent.PreviousNode = noneUUID
	// userlib.DebugMsg(string(fileContent.Content))
	// userlib.DebugMsg(fileContent.PreviousNode.String())

	// Generate key to encrypt FileContent
	fileContentSalt := userlib.RandomBytes(Length)
	fileContentKey, _ := userlib.HashKDF(sharingKey, fileContentSalt)

	// Encrypt FileContent
	serialized_fileContent_struct, _ := json.Marshal(fileContent)
	encrypt_fileContent := userlib.SymEnc(fileContentKey[:16], userlib.RandomBytes(Length), serialized_fileContent_struct)

	// Initialize fileNode struct.
	var node FileNode
	node.Encrypt_FileContent = encrypt_fileContent
	node.FileSalt = fileContentSalt
	node.HMACSalt = userlib.RandomBytes(Length)

	// Store file node to datastore
	serialized_node, _ := json.Marshal(node)
	userlib.DatastoreSet(uuidNode, serialized_node)

	//store fileNode hmac to datastore
	hmacKey, _ := userlib.HashKDF(sharingKey, node.HMACSalt)
	fileNode_hmac_val, _ := userlib.HMACEval(hmacKey[:16], serialized_node)
	fileNodeUUIDHMAC := getUUIDFromString(uuidNode.String() + "/HMACFileNode")
	userlib.DatastoreSet(fileNodeUUIDHMAC, fileNode_hmac_val)

	// Encrypt FileStruct
	fileSalt := userlib.RandomBytes(Length)
	file_key, _ := userlib.HashKDF(sharingKey, fileSalt)

	serialized_fileStruct, err := json.Marshal(fileStruct)
	encrypt_fileStruct := userlib.SymEnc(file_key[:16], userlib.RandomBytes(Length), serialized_fileStruct)

	// Initialize fileMetadata struct and store it in DATASTORE
	hmacFileSalt := userlib.RandomBytes(Length)
	var fileMetadata FileMetadata
	fileMetadata.HMACSalt = hmacFileSalt
	fileMetadata.Encrypt_FileStruct = encrypt_fileStruct
	fileMetadata.FileSalt = fileSalt
	fileMetadata.SharingSalt = sharingSalt

	serialized_fileMetadata, _ := json.Marshal(fileMetadata)
	userlib.DatastoreSet(metadata_UUID, serialized_fileMetadata)

	//HMAC fileMetadata to make sure that it is not tampered. Store hmac in DATASTORE
	//from TrucV
	// hmac_UUID := getUUIDFromString(userdata.Username + "/" + filename + "/HMACFileMetadata")
	//from TrucN: use metadataUUID.string() instead of filename
	hmac_UUID := getUUIDFromString(userdata.Username + "/" + metadata_UUID.String() + "/HMACFileMetadata")
	hmac_key, _ := userlib.HashKDF(sharingKey, hmacFileSalt)
	hmac_file_val, _ := userlib.HMACEval(hmac_key[:16], serialized_fileMetadata)

	// userlib.DebugMsg(strconv.Itoa(len(hmac_file_val)))
	// userlib.DebugMsg(string(hmac_file_val))

	userlib.DatastoreSet(hmac_UUID, hmac_file_val)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// metadata_UUID := getUUIDFromString(userdata.Username + "/" + filename + "/FileMetadataStruct")
	//From TrucN: get FilemetadataStruct from the invitation instead
	//Download the invitation UUID from invitationUUIDStore
	invitationUUIDStorage := getUUIDFromString(userdata.Username + "/" + filename + "/Invitation")
	serialized_fileInvitationUUID, ok := userlib.DatastoreGet(invitationUUIDStorage)
	if !ok {
		return errors.New("the data does not exist, check the file name.")
	}

	errHMAC := userdata.HMACDownload(invitationUUIDStorage, serialized_fileInvitationUUID, "Invitation UUID Storage")
	if errHMAC != nil {
		return errHMAC
	}
	var fileInvitationUUID uuid.UUID
	e := json.Unmarshal(serialized_fileInvitationUUID, &fileInvitationUUID)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitationUUID.")
		return e
	}

	//download the invitation from invitationUUID
	serialized_invitation, ok1 := userlib.DatastoreGet(fileInvitationUUID)
	if !ok1 {
		return errors.New("Access denied.")
	}

	errHMAC = userdata.HMACDownload(fileInvitationUUID, serialized_invitation, "Invitation Struct")
	if errHMAC != nil {
		return errHMAC
	}
	var invitation Invitation
	e = json.Unmarshal(serialized_invitation, &invitation)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitation.")
		return e
	}

	metadata_UUID := invitation.UUIDFileMetadata
	// check to make sure filename exist. Retrieve FileMetadata from DATASTORE
	metadataJSON, ok := userlib.DatastoreGet(metadata_UUID)
	if !ok {
		userlib.DebugMsg("Filename doesn't exist.")
		return errors.New("Filename doesn't exist.")
	}
	var fileMetadata FileMetadata
	json.Unmarshal(metadataJSON, &fileMetadata)

	// sharingKey will be generated based on owner/invitee
	// sharingKey, _ := userlib.HashKDF(userdata.PasswordHash, fileMetadata.SharingSalt)
	// sharingKey = sharingKey[:16]

	//From TrucN: use sharingkey from invitation instead
	// DecryptedAccessingKey
	oldAccessingKey, err := userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedAccessingKey)
	if err != nil {
		return err
	}

	// DecryptedSharingKey
	sharingKey := userlib.SymDec(oldAccessingKey, invitation.EncryptedSharingKey)

	// Get HMAC of fileMetadata from DATASTORE:
	// hmac_UUID := getUUIDFromString(userdata.Username + "/" + filename + "/HMACFileMetadata")
	//from TrucN: use metadataUUID.string() instead of filename
	hmac_UUID := getUUIDFromString(invitation.OwnnerUsername + "/" + metadata_UUID.String() + "/HMACFileMetadata")
	hmac_val, ok := userlib.DatastoreGet(hmac_UUID)

	if !ok {
		userlib.DebugMsg("Couldn't retrieve data from DATASTORE.")
		return errors.New("Couldn't retrieve data from DATASTORE.")
	}

	// check to make sure that FileMetadata is not tampered.
	hmac_key, _ := userlib.HashKDF(sharingKey, fileMetadata.HMACSalt)
	computed_hmac_val, _ := userlib.HMACEval(hmac_key[:16], metadataJSON)

	// userlib.DebugMsg("Check HMAC VAL for FileMetadata Struct")
	if !userlib.HMACEqual(computed_hmac_val, hmac_val) {
		userlib.DebugMsg("Datastore is tampered.")
		return errors.New("Datastore is tampered.")
	}

	file_key, _ := userlib.HashKDF(sharingKey, fileMetadata.FileSalt)
	fileStructJSON := userlib.SymDec(file_key[:16], fileMetadata.Encrypt_FileStruct)

	var fileStruct File
	json.Unmarshal(fileStructJSON, &fileStruct)

	// Node uuid
	uuid := uuid.New()

	var fileContent FileContent
	fileContent.Content = content
	fileContent.PreviousNode = fileStruct.Last_Node

	// update FileStruct
	fileStruct.Last_Node = uuid

	// Generate key to encrypt FileContent
	fileContentSalt := userlib.RandomBytes(Length)
	fileContentKey, _ := userlib.HashKDF(sharingKey, fileContentSalt)

	// Encrypt FileContent
	serialized_fileContent_struct, _ := json.Marshal(fileContent)
	encrypt_fileContent := userlib.SymEnc(fileContentKey[:16], userlib.RandomBytes(Length), serialized_fileContent_struct)

	// Initialize fileNode struct.
	var node FileNode
	node.Encrypt_FileContent = encrypt_fileContent
	node.FileSalt = fileContentSalt
	node.HMACSalt = userlib.RandomBytes(Length)

	// Store file node to datastore
	serialized_node, _ := json.Marshal(node)
	userlib.DatastoreSet(uuid, serialized_node)

	//store fileNode hmac to datastore
	hmacKey, _ := userlib.HashKDF(sharingKey, node.HMACSalt)
	fileNode_hmac_val, _ := userlib.HMACEval(hmacKey[:16], serialized_node)
	fileNodeUUIDHMAC := getUUIDFromString(uuid.String() + "/HMACFileNode")
	userlib.DatastoreSet(fileNodeUUIDHMAC, fileNode_hmac_val)

	serialized_fileStruct, _ := json.Marshal(fileStruct)
	encrypt_fileStruct := userlib.SymEnc(file_key[:16], userlib.RandomBytes(Length), serialized_fileStruct)

	//update encrypt FileStruct and store it in DATASTORE
	fileMetadata.Encrypt_FileStruct = encrypt_fileStruct
	serialized_fileMetadata, _ := json.Marshal(fileMetadata)
	userlib.DatastoreSet(metadata_UUID, serialized_fileMetadata)

	//HMAC fileMetadata to make sure that it is not tampered. Store hmac in DATASTORE
	hmac_file_val, _ := userlib.HMACEval(hmac_key[:16], serialized_fileMetadata)

	// userlib.DebugMsg(strconv.Itoa(len(hmac_file_val)))
	// userlib.DebugMsg(string(hmac_file_val))

	userlib.DatastoreSet(hmac_UUID, hmac_file_val)
	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//metadata_UUID := getUUIDFromString(userdata.Username + "/" + filename + "/FileMetadataStruct")
	//From TrucN: get FilemetadataStruct from the invitation instead
	//Download the invitation UUID from invitationUUIDStore
	invitationUUIDStorage := getUUIDFromString(userdata.Username + "/" + filename + "/Invitation")
	serialized_fileInvitationUUID, ok := userlib.DatastoreGet(invitationUUIDStorage)
	if !ok {
		return nil, errors.New("the data does not exist, check the file name.")
	}

	errHMAC := userdata.HMACDownload(invitationUUIDStorage, serialized_fileInvitationUUID, "Invitation UUID")
	if errHMAC != nil {
		return nil, errHMAC
	}
	var fileInvitationUUID uuid.UUID
	e := json.Unmarshal(serialized_fileInvitationUUID, &fileInvitationUUID)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitationUUID.")
		return nil, e
	}

	//download the invitation from invitationUUID

	serialized_invitation, ok1 := userlib.DatastoreGet(fileInvitationUUID)
	if !ok1 {
		return nil, errors.New("Access denied.")
	}

	errHMAC = userdata.HMACDownload(fileInvitationUUID, serialized_invitation, "Invitation")
	if errHMAC != nil {
		return nil, errHMAC
	}
	var invitation Invitation
	e = json.Unmarshal(serialized_invitation, &invitation)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitation.")
		return nil, e
	}

	metadata_UUID := invitation.UUIDFileMetadata

	// check to make sure filename exist. Retrieve FileMetadata from DATASTORE
	metadataJSON, ok := userlib.DatastoreGet(metadata_UUID)
	if !ok {
		userlib.DebugMsg("Filename doesn't exist.")
		return nil, errors.New("Filename doesn't exist.")
	}
	var fileMetadata FileMetadata
	json.Unmarshal(metadataJSON, &fileMetadata)

	// sharingKey will be generated based on owner/invitee
	// sharingKey, _ := userlib.HashKDF(userdata.PasswordHash, fileMetadata.SharingSalt)
	// sharingKey = sharingKey[:16]

	//From TrucN: use sharingkey from invitation instead
	// DecryptedAccessingKey
	oldAccessingKey, err := userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedAccessingKey)
	if err != nil {
		return nil, errors.New("Can not decrypt Accessing key.")
	}

	// DecryptedSharingKey
	sharingKey := userlib.SymDec(oldAccessingKey, invitation.EncryptedSharingKey)

	// Get HMAC of fileMetadata from DATASTORE:
	// hmac_UUID := getUUIDFromString(userdata.Username + "/" + filename + "/HMACFileMetadata")
	//from TrucN: use metadataUUID.string() instead of filename
	hmac_UUID := getUUIDFromString(invitation.OwnnerUsername + "/" + metadata_UUID.String() + "/HMACFileMetadata")
	hmac_val, ok := userlib.DatastoreGet(hmac_UUID)

	if !ok {
		userlib.DebugMsg("Couldn't retrieve data from DATASTORE.")
		return nil, errors.New("Couldn't retrieve data from DATASTORE.")
	}

	// check to make sure that FileMetadata is not tampered.
	hmac_key, _ := userlib.HashKDF(sharingKey, fileMetadata.HMACSalt)
	computed_hmac_val, _ := userlib.HMACEval(hmac_key[:16], metadataJSON)

	// userlib.DebugMsg("Check HMAC VAL for FileMetadata Struct")
	if !userlib.HMACEqual(computed_hmac_val, hmac_val) {
		userlib.DebugMsg("Datastore is tampered (loadFile/HMACFileMetadata).")
		return content, errors.New("Datastore is tampered (loadFile/HMACFileMetadata).")
	}

	noneUUID := getUUIDFromString("0")

	file_key, _ := userlib.HashKDF(sharingKey, fileMetadata.FileSalt)
	fileStructJSON := userlib.SymDec(file_key[:16], fileMetadata.Encrypt_FileStruct)

	var fileStruct File
	json.Unmarshal(fileStructJSON, &fileStruct)
	nodeUUID := fileStruct.Last_Node

	for nodeUUID != noneUUID {
		// get fileNode
		serialized_fileNode, ok := userlib.DatastoreGet(nodeUUID)
		if !ok {
			userlib.DebugMsg("Coudn't retrieve FileJSON in DATASTORE.")
			return content, nil
		}
		var fileNode FileNode
		json.Unmarshal(serialized_fileNode, &fileNode)
		// userlib.DebugMsg(string(fileNodeJSON))

		// Check to make sure that encrypt_FileContent is not tampered.
		hmac_fileNode_key := getKeyFromSourceKey(sharingKey, fileNode.HMACSalt)
		computed_hmac_file_val, e2 := userlib.HMACEval(hmac_fileNode_key, serialized_fileNode)

		if e2 != nil {
			return content, nil
		}

		fileNodeUUIDHMAC := getUUIDFromString(nodeUUID.String() + "/HMACFileNode")
		// userlib.DebugMsg(fileNodeUUIDHMAC.String())
		hmac_fileNode_val, ok := userlib.DatastoreGet(fileNodeUUIDHMAC)
		if !ok {
			userlib.DebugMsg("Can't retreive fileNodeHMAC from DATASTORE")
			return content, errors.New("Can't not retrieve data from DATASTORE")
		}

		if !userlib.HMACEqual(hmac_fileNode_val, computed_hmac_file_val) {
			// userlib.DebugMsg(string(hmac_fileNode_val))
			userlib.DebugMsg("Datastore is tampered (loadFIle/fileNodeHmac).")
			return content, errors.New("Datastore is tampered.")
		}

		fileContentKey, _ := userlib.HashKDF(sharingKey, fileNode.FileSalt)
		encrypt_json_fileContent := userlib.SymDec(fileContentKey[:16], fileNode.Encrypt_FileContent)
		var fileContent FileContent
		json.Unmarshal(encrypt_json_fileContent, &fileContent)

		// userlib.DebugMsg(fileContent.PreviousNode.String())
		// userlib.DebugMsg(string(fileContent.Content))
		temp := string(fileContent.Content) + string(content)
		content = []byte(temp)
		nodeUUID = fileContent.PreviousNode
	}
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//Download the invitation UUID from invitationUUIDStore
	invitationUUIDStorage := getUUIDFromString(userdata.Username + "/" + filename + "/Invitation")
	serialized_fileInvitationUUID, ok := userlib.DatastoreGet(invitationUUIDStorage)
	if !ok {
		return uuid.Nil, errors.New("the data does not exist, check the file name.")
	}

	errHMAC := userdata.HMACDownload(invitationUUIDStorage, serialized_fileInvitationUUID, "Invitation UUID")
	if errHMAC != nil {
		return uuid.Nil, errHMAC
	}
	var fileInvitationUUID uuid.UUID
	e := json.Unmarshal(serialized_fileInvitationUUID, &fileInvitationUUID)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitationUUID.")
		return uuid.Nil, e
	}

	//download the invitation from invitationUUID

	serialized_invitation, ok1 := userlib.DatastoreGet(fileInvitationUUID)
	if !ok1 {
		return uuid.Nil, errors.New("Access denied.")
	}

	errHMAC = userdata.HMACDownload(fileInvitationUUID, serialized_invitation, "Invitation")
	if errHMAC != nil {
		return uuid.Nil, errHMAC
	}
	var invitation Invitation
	e = json.Unmarshal(serialized_invitation, &invitation)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitation.")
		return uuid.Nil, e
	}
	//create new invitation

	var newInvitation Invitation
	newInvitation.OwnnerUsername = invitation.OwnnerUsername
	newInvitation.Sender = userdata.Username
	newInvitation.Invitee = recipientUsername
	newInvitation.UUIDFileMetadata = invitation.UUIDFileMetadata
	newInvitation.Accepted = false

	// DecryptedAccessingKey
	oldAccessingKey, err := userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedAccessingKey)
	if err != nil {
		return uuid.Nil, errors.New("Cannot decrypt accesing key")
	}

	// DecryptedSharingKey
	sharingKey := userlib.SymDec(oldAccessingKey, invitation.EncryptedSharingKey)

	// Use invitee pk to encrypt AccessingKey and sharingKey
	pk, ok := userlib.KeystoreGet(recipientUsername)
	iv := userlib.RandomBytes(16)
	accessingKey := userlib.RandomBytes(16)
	newInvitation.EncryptedSharingKey = userlib.SymEnc(accessingKey, iv, sharingKey)
	newInvitation.EncryptedAccessingKey, err = userlib.PKEEnc(pk, accessingKey)

	//upload newInvitation to datastore
	newInvitationUUID := uuid.New()

	serialized_newInvitation, _ := json.Marshal(newInvitation)

	userlib.DatastoreSet(newInvitationUUID, serialized_newInvitation)
	userdata.HMACUpload(newInvitationUUID, serialized_newInvitation)

	//create newChildrenList and upload to dataStore
	newChildrenListUUID := getUUIDFromString(newInvitationUUID.String() + "/ChildrenList")
	var newChildrenList []uuid.UUID
	serialized_newChildrenList, _ := json.Marshal(newChildrenList)
	userlib.DatastoreSet(newChildrenListUUID, serialized_newChildrenList)
	userdata.HMACUpload(newChildrenListUUID, serialized_newChildrenList)

	//append to childrenlist of owner invitation
	childrenListUUID := getUUIDFromString(fileInvitationUUID.String() + "/ChildrenList")
	serialized_childrenList, ok := userlib.DatastoreGet(childrenListUUID)
	if !ok {
		userlib.DebugMsg("The childrenList does not exist.")
		return uuid.Nil, e
	}
	errHMAC = userdata.HMACDownload(childrenListUUID, serialized_childrenList, "Children List")

	if errHMAC != nil {
		return uuid.Nil, errHMAC
	}
	var childrenList []uuid.UUID
	e = json.Unmarshal(serialized_childrenList, &childrenList)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the childrenList.")
		return uuid.Nil, e
	}

	childrenList = append(childrenList, newInvitationUUID)

	serialized_childrenList, _ = json.Marshal(childrenList)
	userlib.DatastoreSet(childrenListUUID, serialized_childrenList)
	userdata.HMACUpload(childrenListUUID, serialized_childrenList)

	return newInvitationUUID, nil

}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//Download the invitation
	serialized_invitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Access denied.")
	}
	errHMAC := userdata.HMACDownload(invitationPtr, serialized_invitation, "Invitation")
	if errHMAC != nil {
		return errHMAC
	}
	var invitation Invitation
	e := json.Unmarshal(serialized_invitation, &invitation)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitation.")
		return errors.New("Could not unmarshall the invitation.")
	}
	if invitation.Invitee != userdata.Username {
		return errors.New("Wrong invitation.")
	}
	if invitation.Sender != senderUsername {
		return errors.New("Wrong invitation.")
	}

	//Change Accepted to true and update to datastore
	invitation.Accepted = true
	serialized_invitation, _ = json.Marshal(invitation)
	userlib.DatastoreSet(invitationPtr, serialized_invitation)
	userdata.HMACUpload(invitationPtr, serialized_invitation)

	// update invitation map with new filename
	invitattionUUIDStorage := getUUIDFromString(userdata.Username + "/" + filename + "/Invitation")
	serialized_invitationPtr, _ := json.Marshal(invitationPtr)
	userlib.DatastoreSet(invitattionUUIDStorage, serialized_invitationPtr)
	userdata.HMACUpload(invitattionUUIDStorage, serialized_invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	invitationUUIDStorage := getUUIDFromString(userdata.Username + "/" + filename + "/Invitation")
	serialized_fileInvitationUUID, ok := userlib.DatastoreGet(invitationUUIDStorage)
	if !ok {
		return errors.New("the data does not exist, check the file name.")
	}

	errHMAC := userdata.HMACDownload(invitationUUIDStorage, serialized_fileInvitationUUID, "Invitation UUID")
	if errHMAC != nil {
		return errHMAC
	}
	var fileInvitationUUID uuid.UUID
	e := json.Unmarshal(serialized_fileInvitationUUID, &fileInvitationUUID)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitationUUID.")
		return e
	}

	//download the invitation from invitationUUID

	serialized_invitation, ok1 := userlib.DatastoreGet(fileInvitationUUID)
	if !ok1 {
		return errors.New("Access denied.")
	}

	errHMAC = userdata.HMACDownload(fileInvitationUUID, serialized_invitation, "Invitation")
	if errHMAC != nil {
		return errHMAC
	}
	var invitation Invitation
	e = json.Unmarshal(serialized_invitation, &invitation)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitation.")
		return e
	}

	//check if the user is fileowner
	if userdata.Username != invitation.OwnnerUsername {
		userlib.DebugMsg("User is not the file owner.")
		return errors.New("User is not the file owner.")
	}

	//get the childrenList of invitation
	childrenListUUID := getUUIDFromString(fileInvitationUUID.String() + "/ChildrenList")
	serialized_childrenList, ok := userlib.DatastoreGet(childrenListUUID)
	if !ok {
		userlib.DebugMsg("The childrenList does not exist.")
		return e
	}

	errHMAC = userdata.HMACDownload(childrenListUUID, serialized_childrenList, "Children List")
	if errHMAC != nil {
		return errHMAC
	}
	var childrenList []uuid.UUID
	e = json.Unmarshal(serialized_childrenList, &childrenList)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the childrenList.")
		return e
	}

	//Get the index of revokedChild and get the revokedInvitationUUID
	revokedChildnum := len(childrenList) + 100
	for i := 0; i < len(childrenList); i++ {
		serialized_childInvitation, ok := userlib.DatastoreGet(childrenList[i])
		if !ok {
			return errors.New("the invitation does not exist on Datastore.")
		}

		errHMAC = userdata.HMACDownload(childrenList[i], serialized_childInvitation, "child Invitation")
		if errHMAC != nil {
			return errHMAC
		}
		var childInvitation Invitation
		e = json.Unmarshal(serialized_childInvitation, &childInvitation)
		if e != nil {
			userlib.DebugMsg("Could not unmarshall the childInvitation.")
			return e
		}
		// userlib.DebugMsg("Invitee: %v", childInvitation.Invitee)
		if childInvitation.Invitee == recipientUsername {
			revokedChildnum = i
			break
		}
	}
	if revokedChildnum > len(childrenList) {
		return errors.New("Recipient was not invited.")
	}
	revokedChildUUID := childrenList[revokedChildnum]
	//recursive delete the invitation
	err := userdata.recursiveDelete(revokedChildUUID)
	if err != nil {
		return err
	}
	//update the sharingKey and encrypt all Data again

	//temporary sharingKey
	// oldAccessingKey, err := userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedAccessingKey)
	// if err != nil {
	// 	panic("Cannot decrypt accesing key")
	// }

	// DecryptedSharingKey
	sharingKey, e1 := userdata.updateEncryption(invitation.UUIDFileMetadata)
	if e1 != nil {
		return e1
	}

	//update the childrenList
	childrenList = append(childrenList[:revokedChildnum], childrenList[revokedChildnum+1:]...)

	//upload datastore
	serialized_childrenList, _ = json.Marshal(childrenList)
	userlib.DatastoreSet(childrenListUUID, serialized_childrenList)
	userdata.HMACUpload(childrenListUUID, serialized_childrenList)

	//recursive update all invitation with new Sharingkey
	err = userdata.recursiveUpdate(fileInvitationUUID, sharingKey)
	if err != nil {
		return err
	}
	return nil
}

//HMAC upload
func (user *User) HMACUpload(fileUUID uuid.UUID, value []byte) {
	newUUID := getUUIDFromString(fileUUID.String() + "HMAC_val")
	rand16Byte := userlib.RandomBytes(16)
	hmacVal, err := userlib.HMACEval(rand16Byte, value)
	if err != nil {
		panic(errors.New("An error occurred while generating HMAC value"))
	}
	uploadVal := append(rand16Byte, hmacVal...)
	userlib.DatastoreSet(newUUID, uploadVal)

}

//HMAC download and verify
func (user *User) HMACDownload(file uuid.UUID, downloadVal []byte, source string) error {
	//(equal bool) {

	newUUID := getUUIDFromString(file.String() + "HMAC_val")
	hmacDownloadVal, ok := userlib.DatastoreGet(newUUID)
	if !ok {
		return errors.New("the data does not exist.")
	}

	if hmacDownloadVal == nil || len(hmacDownloadVal) != 80 {
		return errors.New("Datastore is tampered.")
	}
	// userlib.DebugMsg(strconv.Itoa(len(hmacDownloadVal)))
	rand16Byte := hmacDownloadVal[0:16]
	hmacVal := hmacDownloadVal[16:]
	downloadHMACVal, err := userlib.HMACEval(rand16Byte, downloadVal)
	if err != nil {
		return errors.New("An error occurred while generating HMAC value")
	}
	// userlib.DebugMsg("Compare HMACval: %v, %v", downloadHMACVal, hmacVal )
	changed := !userlib.HMACEqual(downloadHMACVal, hmacVal)

	if changed {
		return errors.New("DATASTORE is tampered")
	}
	return nil

}

//recursive delete invitation and its children
func (userdata *User) recursiveDelete(invitationUUID uuid.UUID) error {
	childrenListUUID := getUUIDFromString(invitationUUID.String() + "/ChildrenList")
	serialized_childrenList, ok := userlib.DatastoreGet(childrenListUUID)
	if !ok {
		userlib.DebugMsg("The childrenList does not exist.")
		return errors.New("The childrenList does not exist.")
	}
	errHMAC := userdata.HMACDownload(childrenListUUID, serialized_childrenList, "Children List")
	if errHMAC != nil {
		return errHMAC
	}
	var childrenList []uuid.UUID
	e := json.Unmarshal(serialized_childrenList, &childrenList)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the childrenList.")
		return errors.New("Could not unmarshall the childrenList.")
	}
	for i := 0; i < len(childrenList); i++ {
		userdata.recursiveDelete(childrenList[i])
	}
	userlib.DatastoreDelete(invitationUUID)
	userlib.DatastoreDelete(childrenListUUID)
	hmacUUID := getUUIDFromString(invitationUUID.String() + "HMAC_val")
	userlib.DatastoreDelete(hmacUUID)
	return nil
}

//recursive update invitation and its children with new sharingKey
func (userdata *User) recursiveUpdate(invitationUUID uuid.UUID, sharingKey []byte) error {
	//traverse down the tree
	childrenListUUID := getUUIDFromString(invitationUUID.String() + "/ChildrenList")
	serialized_childrenList, ok := userlib.DatastoreGet(childrenListUUID)
	if !ok {
		userlib.DebugMsg("The childrenList does not exist.")
		return errors.New("The childrenList does not exist.")
	}
	errHMAC := userdata.HMACDownload(childrenListUUID, serialized_childrenList, "Children List")
	if errHMAC != nil {
		return errHMAC
	}

	var childrenList []uuid.UUID
	e := json.Unmarshal(serialized_childrenList, &childrenList)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the childrenList.")
		return errors.New("Could not unmarshall the childrenList.")
	}
	for i := 0; i < len(childrenList); i++ {
		userdata.recursiveUpdate(childrenList[i], sharingKey)
	}

	//Download the invitation and update new key
	serialized_invitation, ok1 := userlib.DatastoreGet(invitationUUID)
	if !ok1 {
		return errors.New("You are revoked or did not accept the invitation.")
	}

	errHMAC = userdata.HMACDownload(invitationUUID, serialized_invitation, "Invitation")
	if errHMAC != nil {
		return errHMAC
	}
	var invitation Invitation
	e = json.Unmarshal(serialized_invitation, &invitation)
	if e != nil {
		userlib.DebugMsg("Could not unmarshall the invitation.")
		return e
	}

	pk, ok := userlib.KeystoreGet(invitation.Invitee)
	if !ok {
		userlib.DebugMsg("Can not get invitee from DATASTORE")
		return nil
	}

	iv := userlib.RandomBytes(16)
	accessingKey := userlib.RandomBytes(16)
	invitation.EncryptedSharingKey = userlib.SymEnc(accessingKey, iv, sharingKey)
	var err error
	invitation.EncryptedAccessingKey, err = userlib.PKEEnc(pk, accessingKey)
	if err != nil {
		userlib.DebugMsg("Can not encrypt AccessingKey")
		return err
	}

	serialized_invitation, _ = json.Marshal(invitation)

	userlib.DatastoreSet(invitationUUID, serialized_invitation)
	userdata.HMACUpload(invitationUUID, serialized_invitation)

	return nil
}

func (userdata *User) updateSharingKey(fileMetadata FileMetadata, sharingSalt []byte) (newSharingKey []byte, oldSharingKey []byte) {
	// generate old/new sharingKey on a fly
	oldSharingKey = getKeyFromSourceKey(userdata.PasswordHash, fileMetadata.SharingSalt)
	newSharingKey = getKeyFromSourceKey(userdata.PasswordHash, sharingSalt)
	return newSharingKey, oldSharingKey
}

// Re-encrypt fileMetadata and FileNode with new sharing key when an user is revoked. Return new sharing key
func (userdata *User) updateEncryption(fileMetadata_UUID uuid.UUID) ([]byte, error) {
	// get FileMetadata
	metadataJSON, ok := userlib.DatastoreGet(fileMetadata_UUID)
	if !ok {
		userlib.DebugMsg("FileMetadata doesn't exist.")
		return nil, errors.New("FileMetadata doesn't exist")
	}

	// check HMACFileMetadata to make sure that DATASTORE is not tampered.
	hmac_UUID := getUUIDFromString(userdata.Username + "/" + fileMetadata_UUID.String() + "/HMACFileMetadata")
	hmac_val, ok := userlib.DatastoreGet(hmac_UUID)
	if !ok {
		userlib.DebugMsg("Couldn't retrieve data from DATASTORE.")
		return nil, nil
	}
	var fileMetadata FileMetadata
	json.Unmarshal(metadataJSON, &fileMetadata)

	// get oldSharingKey and newSharingKey
	newSharingKey, oldSharingKey := userdata.updateSharingKey(fileMetadata, userlib.RandomBytes(Length))

	// check to make sure that FileMetadata is not tampered.

	hmac_key := getKeyFromSourceKey(oldSharingKey, fileMetadata.HMACSalt)
	computed_hmac_val, _ := userlib.HMACEval(hmac_key, metadataJSON)

	if !userlib.HMACEqual(computed_hmac_val, hmac_val) {
		userlib.DebugMsg("Datastore is tampered (updateEncryption/fileMetadata).")
		return nil, nil
	}

	// re-encrypt fileStruct using newSharingKey
	nodeUUID, e1 := userdata.updateFileMetadataEncryption(fileMetadata_UUID, fileMetadata, newSharingKey, oldSharingKey)
	if e1 != nil {
		return nil, e1
	}
	// re-encrypt fileContentStruct using newSharingKey
	noneUUID := getUUIDFromString("0")

	for nodeUUID != noneUUID {
		newNodeUUID, e2 := updateFileNodeEncryption(nodeUUID, newSharingKey, oldSharingKey)
		// userlib.DebugMsg(nodeUUID.String())
		if e2 != nil {
			return nil, e2
		}
		nodeUUID = newNodeUUID
	}

	return newSharingKey, nil

}

func getKeyFromSourceKey(sourceKey []byte, salt []byte) (sharingKey []byte) {
	var err error
	sharingKey, err = userlib.HashKDF(sourceKey, salt)
	if err != nil {
		userlib.DebugMsg("Could not generate key from sourceKey.")
	}
	return sharingKey[:16]
}

// update FileMetadata encryption and HMAC
func (userdata *User) updateFileMetadataEncryption(fileMetadata_UUID uuid.UUID, fileMetadata FileMetadata, newSharingKey []byte, oldSharingKey []byte) (lastNode uuid.UUID, err error) {
	// decrypt FileStruct and get the last node
	file_key := getKeyFromSourceKey(oldSharingKey, fileMetadata.FileSalt)
	fileStructJSON := userlib.SymDec(file_key, fileMetadata.Encrypt_FileStruct)
	var fileStruct File
	e1 := json.Unmarshal(fileStructJSON, &fileStruct)
	if e1 != nil {
		userlib.DebugMsg("Error at updateFileMetadataEncryption")
		return uuid.Nil, e1
	}

	// encrypt FileStruct again and store it in DATASTORE
	file_key = getKeyFromSourceKey(newSharingKey, fileMetadata.FileSalt)
	fileMetadata.Encrypt_FileStruct = userlib.SymEnc(file_key, userlib.RandomBytes(Length), fileStructJSON)
	fileMetadataJSON, e2 := json.Marshal(fileMetadata)
	if e2 != nil {
		return uuid.Nil, e2
	}
	userlib.DatastoreSet(fileMetadata_UUID, fileMetadataJSON)

	// update FileMetadataHMAC
	serialized_fileMetadata, e3 := json.Marshal(fileMetadata)
	if e3 != nil {
		return uuid.Nil, e3
	}

	hmac_UUID := getUUIDFromString(userdata.Username + "/" + fileMetadata_UUID.String() + "/HMACFileMetadata")
	hmac_key := getKeyFromSourceKey(newSharingKey, fileMetadata.HMACSalt)
	hmac_file_val, _ := userlib.HMACEval(hmac_key[:16], serialized_fileMetadata)
	userlib.DatastoreSet(hmac_UUID, hmac_file_val)

	return fileStruct.Last_Node, nil

}

// update FileNode encryption and HMAC
func updateFileNodeEncryption(nodeUUID uuid.UUID, newSharingKey []byte, oldSharingKey []byte) (uuid.UUID, error) {
	// get fileNode
	fileNodeJSON, ok := userlib.DatastoreGet(nodeUUID)
	if !ok {
		userlib.DebugMsg("Coudn't retrieve FileJSON in DATASTORE.")
		return uuid.Nil, errors.New("Coudn't retrieve FileJSON in DATASTORE.")
	}
	var fileNode FileNode
	e1 := json.Unmarshal(fileNodeJSON, &fileNode)
	if e1 != nil {
		userlib.DebugMsg("Error at updateFileNodeEncryption.")
		return uuid.Nil, errors.New("couldn't unmarshal")
	}

	// Check to make sure that fileNode is not tampered.
	hmac_fileNode_key, _ := userlib.HashKDF(oldSharingKey, fileNode.HMACSalt)

	fileNodeUUIDHMAC := getUUIDFromString(nodeUUID.String() + "/HMACFileNode")
	hmac_fileNode_val, ok := userlib.DatastoreGet(fileNodeUUIDHMAC)
	if !ok {
		userlib.DebugMsg("Can'tnot retreive fileNodeHMAC from DATASTORE")
		return uuid.Nil, errors.New("Can't not retrieve data from DATASTORE")
	}

	computed_hmac_val, _ := userlib.HMACEval(hmac_fileNode_key[:16], fileNodeJSON)

	if !userlib.HMACEqual(hmac_fileNode_val, computed_hmac_val) {
		userlib.DebugMsg("Datastore is tampered.")
		return uuid.Nil, errors.New("Datastore is tampered.")
	}

	fileContentKey := getKeyFromSourceKey(oldSharingKey, fileNode.FileSalt)
	encrypt_json_fileContent := userlib.SymDec(fileContentKey, fileNode.Encrypt_FileContent)

	// get previous node uuid
	var fileContent FileContent
	json.Unmarshal(encrypt_json_fileContent, &fileContent)
	// nodeUUID = fileContent.PreviousNode

	// re-encrypt FileContent
	newFileContentKey := getKeyFromSourceKey(newSharingKey, fileNode.FileSalt)
	fileNode.Encrypt_FileContent = userlib.SymEnc(newFileContentKey, userlib.RandomBytes(Length), encrypt_json_fileContent)

	// Store FileNode in DATASTORE
	serialized_fileNode, _ := json.Marshal(fileNode)
	userlib.DatastoreSet(nodeUUID, serialized_fileNode)

	// update HMAC of FileNode with new sharing key
	hmac_fileNode_key = getKeyFromSourceKey(newSharingKey, fileNode.HMACSalt)
	computed_hmac_val, _ = userlib.HMACEval(hmac_fileNode_key, serialized_fileNode)

	// store HMAC val in DATASTORE
	userlib.DatastoreSet(fileNodeUUIDHMAC, computed_hmac_val)
	// userlib.DebugMsg(fileNodeUUIDHMAC.String())

	nodeUUID = fileContent.PreviousNode
	return nodeUUID, nil

}
