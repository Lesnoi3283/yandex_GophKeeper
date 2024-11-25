package grpchandlers

import (
	"GophKeeper/internal/app/gRPC/interceptors"
	"GophKeeper/internal/app/gRPC/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
)

// GetBinData streams encrypted binary data to the client.
func (s *GophKeeperServer) GetBinData(req *proto.GetBinDataRequest, stream proto.GophKeeperService_GetBinDataServer) error {
	// Get userID from context
	userID := stream.Context().Value(interceptors.ContextUserIDKey)
	if userID == nil {
		s.logger.Debug("no userID in context")
		return status.Error(codes.Unauthenticated, "Authentication required")
	}
	userIDStr, ok := userID.(string)
	if !ok {
		s.logger.Error("userID is not a string")
		return status.Error(codes.Internal, "Internal server error")
	}

	// Validate the data name
	dataName := req.GetDataName()
	if dataName == "" {
		s.logger.Error("dataName is empty")
		return status.Error(codes.InvalidArgument, "Data name is required")
	}

	// Get encryption key
	key, err := s.keyKeeper.GetBinaryDataKey(userIDStr, dataName)
	if err != nil {
		if s.logger.Level() != zap.DebugLevel {
			s.logger.Errorf("Failed to get binary data key")
		} else {
			s.logger.Debugf("Failed to get binary data key, err: %v", err)
		}
		return status.Error(codes.Internal, "Internal server error")
	}

	// Open encrypted file for reading
	encReader, err := s.encryptionRWFabric.CreateNewEncryptedReader(userIDStr, dataName, []byte(key))
	if err != nil {
		if s.logger.Level() != zap.DebugLevel {
			s.logger.Errorf("Failed to create encrypted reader")
		} else {
			s.logger.Debugf("Failed to create encrypted reader, err: %v", err)
		}
		return status.Error(codes.Internal, "Internal server error")
	}
	defer encReader.Close()

	// Buffer to read chunks
	buf := make([]byte, s.maxBinDataChunkSize)
	for {
		// Read a chunk from the file
		n, err := encReader.Read(buf)
		if err == io.EOF {
			// Success
			return status.Error(codes.OK, "ok")
		}
		if err != nil {
			if s.logger.Level() != zap.DebugLevel {
				s.logger.Errorf("Failed to read chunk from file")
			} else {
				s.logger.Debugf("Failed to read chunk from file, err: %v", err)
			}
			return status.Error(codes.Internal, "Failed to read binary data")
		}

		// Send the chunk
		response := &proto.GetBinDataResponse{
			Chunk: buf[:n], // Only send the bytes that were read
		}
		if err := stream.Send(response); err != nil {
			if s.logger.Level() != zap.DebugLevel {
				s.logger.Errorf("Failed to send chunk to client")
			} else {
				s.logger.Debugf("Failed to send chunk to client, err: %v", err)
			}
			return status.Error(codes.Internal, "Failed to stream binary data")
		}
	}

	return nil
}
