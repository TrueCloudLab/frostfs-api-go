// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.9
// source: tombstone/grpc/types.proto

package tombstone

import (
	grpc "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Tombstone keeps record of deleted objects for a few epochs until they are
// purged from the NeoFS network.
type Tombstone struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Last NeoFS epoch number of the tombstone lifetime. It's set by the tombstone
	// creator depending on the current NeoFS network settings. A tombstone object
	// must have the same expiration epoch value in `__NEOFS__EXPIRATION_EPOCH`
	// attribute. Otherwise, the tombstone will be rejected by a storage node.
	ExpirationEpoch uint64 `protobuf:"varint,1,opt,name=expiration_epoch,json=expirationEpoch,proto3" json:"expiration_epoch,omitempty"`
	// 16 byte UUID used to identify the split object hierarchy parts. Must be
	// unique inside a container. All objects participating in the split must
	// have the same `split_id` value.
	SplitId []byte `protobuf:"bytes,2,opt,name=split_id,json=splitID,proto3" json:"split_id,omitempty"`
	// List of objects to be deleted.
	Members []*grpc.ObjectID `protobuf:"bytes,3,rep,name=members,proto3" json:"members,omitempty"`
}

func (x *Tombstone) Reset() {
	*x = Tombstone{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tombstone_grpc_types_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Tombstone) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tombstone) ProtoMessage() {}

func (x *Tombstone) ProtoReflect() protoreflect.Message {
	mi := &file_tombstone_grpc_types_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Tombstone.ProtoReflect.Descriptor instead.
func (*Tombstone) Descriptor() ([]byte, []int) {
	return file_tombstone_grpc_types_proto_rawDescGZIP(), []int{0}
}

func (x *Tombstone) GetExpirationEpoch() uint64 {
	if x != nil {
		return x.ExpirationEpoch
	}
	return 0
}

func (x *Tombstone) GetSplitId() []byte {
	if x != nil {
		return x.SplitId
	}
	return nil
}

func (x *Tombstone) GetMembers() []*grpc.ObjectID {
	if x != nil {
		return x.Members
	}
	return nil
}

var File_tombstone_grpc_types_proto protoreflect.FileDescriptor

var file_tombstone_grpc_types_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x74, 0x6f, 0x6d, 0x62, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x6e, 0x65,
	0x6f, 0x2e, 0x66, 0x73, 0x2e, 0x76, 0x32, 0x2e, 0x74, 0x6f, 0x6d, 0x62, 0x73, 0x74, 0x6f, 0x6e,
	0x65, 0x1a, 0x15, 0x72, 0x65, 0x66, 0x73, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x79, 0x70,
	0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x85, 0x01, 0x0a, 0x09, 0x54, 0x6f, 0x6d,
	0x62, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x12, 0x29, 0x0a, 0x10, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x70, 0x6f, 0x63, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x70, 0x6f, 0x63,
	0x68, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x07, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x49, 0x44, 0x12, 0x32, 0x0a, 0x07,
	0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e,
	0x6e, 0x65, 0x6f, 0x2e, 0x66, 0x73, 0x2e, 0x76, 0x32, 0x2e, 0x72, 0x65, 0x66, 0x73, 0x2e, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x44, 0x52, 0x07, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73,
	0x42, 0x64, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x54,
	0x72, 0x75, 0x65, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x4c, 0x61, 0x62, 0x2f, 0x66, 0x72, 0x6f, 0x73,
	0x74, 0x66, 0x73, 0x2d, 0x61, 0x70, 0x69, 0x2d, 0x67, 0x6f, 0x2f, 0x76, 0x32, 0x2f, 0x74, 0x6f,
	0x6d, 0x62, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x3b, 0x74, 0x6f, 0x6d,
	0x62, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0xaa, 0x02, 0x1d, 0x4e, 0x65, 0x6f, 0x2e, 0x46, 0x69, 0x6c,
	0x65, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x41, 0x50, 0x49, 0x2e, 0x54, 0x6f, 0x6d,
	0x62, 0x73, 0x74, 0x6f, 0x6e, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tombstone_grpc_types_proto_rawDescOnce sync.Once
	file_tombstone_grpc_types_proto_rawDescData = file_tombstone_grpc_types_proto_rawDesc
)

func file_tombstone_grpc_types_proto_rawDescGZIP() []byte {
	file_tombstone_grpc_types_proto_rawDescOnce.Do(func() {
		file_tombstone_grpc_types_proto_rawDescData = protoimpl.X.CompressGZIP(file_tombstone_grpc_types_proto_rawDescData)
	})
	return file_tombstone_grpc_types_proto_rawDescData
}

var file_tombstone_grpc_types_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_tombstone_grpc_types_proto_goTypes = []interface{}{
	(*Tombstone)(nil),     // 0: neo.fs.v2.tombstone.Tombstone
	(*grpc.ObjectID)(nil), // 1: neo.fs.v2.refs.ObjectID
}
var file_tombstone_grpc_types_proto_depIdxs = []int32{
	1, // 0: neo.fs.v2.tombstone.Tombstone.members:type_name -> neo.fs.v2.refs.ObjectID
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_tombstone_grpc_types_proto_init() }
func file_tombstone_grpc_types_proto_init() {
	if File_tombstone_grpc_types_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_tombstone_grpc_types_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Tombstone); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_tombstone_grpc_types_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_tombstone_grpc_types_proto_goTypes,
		DependencyIndexes: file_tombstone_grpc_types_proto_depIdxs,
		MessageInfos:      file_tombstone_grpc_types_proto_msgTypes,
	}.Build()
	File_tombstone_grpc_types_proto = out.File
	file_tombstone_grpc_types_proto_rawDesc = nil
	file_tombstone_grpc_types_proto_goTypes = nil
	file_tombstone_grpc_types_proto_depIdxs = nil
}
