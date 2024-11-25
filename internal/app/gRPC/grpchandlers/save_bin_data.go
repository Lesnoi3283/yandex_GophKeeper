package grpchandlers

import (
	"GophKeeper/internal/app/gRPC/interceptors"
	"GophKeeper/internal/app/gRPC/proto"
	"encoding/binary"
	"github.com/golang/protobuf/ptypes/empty"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
)

// SaveBinData encrypts and saves a bin data into a file.
// Authentication required - userID have to be in ctx as a string value.
func (s *GophKeeperServer) SaveBinData(stream grpc.ClientStreamingServer[proto.SaveBinDataRequest, empty.Empty]) error {
	//get userID
	userID := stream.Context().Value(interceptors.ContextUserIDKey)
	if userID == nil {
		s.logger.Debug("no userID in context")
		return status.Error(codes.Unauthenticated, "Authentication required")
	}
	userIDStr, ok := userID.(string)
	if !ok {
		s.logger.Error("userID not int")
		return status.Error(codes.Internal, "Internal server error")
	}

	//prepare encryption writer
	var encWriter io.WriteCloser
	key := make([]byte, chacha20poly1305.KeySize)
	var dataName string

	for {
		req, err := stream.Recv()

		if err == io.EOF { //file saved, return the answer.
			//save key
			err = s.keyKeeper.SetBinaryDataKey(userIDStr, dataName, string(key))
			if err != nil {
				if s.logger.Level() != zap.DebugLevel {
					s.logger.Errorf("cant save binary data key")
				} else {
					s.logger.Debugf("cant save binary data key, err: %v", err)
				}

				return status.Error(codes.Internal, "Internal server error")
			}
			//success
			break
		}
		if err != nil {
			s.logger.Errorf("error while reading stream, err: %v", err)
			return status.Error(codes.Internal, "Internal server error")
		}

		//check size
		if binary.Size(req.Chunk) > binary.Size([1]byte{})*s.maxBinDataChunkSize {
			s.logger.Debugf("too big data chunk, expected size: %v bytes, real size: %v", s.maxBinDataChunkSize, binary.Size(req.Chunk))
			return status.Errorf(codes.InvalidArgument, "Too big data chunk. Max chunk size is %v bytes, your size is %v bytes.", s.maxBinDataChunkSize, binary.Size(req.Chunk))
		}

		//create writer if it`s first chunk
		if len(req.DataName) > 0 && encWriter == nil {
			dataName = req.DataName
			encWriter, key, err = s.encryptionRWFabric.CreateNewEncryptedWriter(userIDStr, dataName)
			if err != nil {
				s.logger.Errorf("error while creating encrypted writer, err: %v", err)
				return status.Error(codes.Internal, "Internal server error")
			}
			defer encWriter.Close()

		} else if len(req.DataName) == 0 && encWriter == nil {
			s.logger.Error("First chunk must contain DataName")
			return status.Error(codes.InvalidArgument, "First chunk must contain DataName")
		}

		//save data
		_, err = encWriter.Write(req.Chunk)
		if err != nil {
			s.logger.Errorf("error while writing chunk, err: %v", err)
			return status.Error(codes.Internal, "Internal server error")
		}
	}

	return nil
}
