package session

import (
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// RequestHeaders represents common part of
// all NeoFS requests including headers.
type RequestHeaders struct {
	metaHeader *RequestMetaHeader

	verifyHeader *RequestVerificationHeader
}

// GetMetaHeader returns meta header of the request.
func (c *RequestHeaders) GetMetaHeader() *RequestMetaHeader {
	if c != nil {
		return c.metaHeader
	}

	return nil
}

// SetMetaHeader sets meta header of the request.
func (c *RequestHeaders) SetMetaHeader(v *RequestMetaHeader) {
	c.metaHeader = v
}

// GetVerificationHeader returns verification header of the request.
func (c *RequestHeaders) GetVerificationHeader() *RequestVerificationHeader {
	if c != nil {
		return c.verifyHeader
	}

	return nil
}

// SetVerificationHeader sets verification header of the request.
func (c *RequestHeaders) SetVerificationHeader(v *RequestVerificationHeader) {
	c.verifyHeader = v
}

func (c *RequestHeaders) ToMessage(m interface {
	SetMetaHeader(*session.RequestMetaHeader)
	SetVerifyHeader(*session.RequestVerificationHeader)
}) {
	m.SetMetaHeader(c.metaHeader.ToGRPCMessage().(*session.RequestMetaHeader))
	m.SetVerifyHeader(c.verifyHeader.ToGRPCMessage().(*session.RequestVerificationHeader))
}

func (c *RequestHeaders) FromMessage(m interface {
	GetMetaHeader() *session.RequestMetaHeader
	GetVerifyHeader() *session.RequestVerificationHeader
}) error {
	metaHdr := m.GetMetaHeader()
	if metaHdr == nil {
		c.metaHeader = nil
	} else {
		if c.metaHeader == nil {
			c.metaHeader = new(RequestMetaHeader)
		}

		err := c.metaHeader.FromGRPCMessage(metaHdr)
		if err != nil {
			return err
		}
	}

	verifyHdr := m.GetVerifyHeader()
	if verifyHdr == nil {
		c.verifyHeader = nil
	} else {
		if c.verifyHeader == nil {
			c.verifyHeader = new(RequestVerificationHeader)
		}

		err := c.verifyHeader.FromGRPCMessage(verifyHdr)
		if err != nil {
			return err
		}
	}

	return nil
}

// ResponseHeaders represents common part of
// all NeoFS responses including headers.
type ResponseHeaders struct {
	metaHeader *ResponseMetaHeader

	verifyHeader *ResponseVerificationHeader
}

// GetMetaHeader returns meta header of the response.
func (c *ResponseHeaders) GetMetaHeader() *ResponseMetaHeader {
	if c != nil {
		return c.metaHeader
	}

	return nil
}

// SetMetaHeader sets meta header of the response.
func (c *ResponseHeaders) SetMetaHeader(v *ResponseMetaHeader) {
	c.metaHeader = v
}

// GetVerificationHeader returns verification header of the response.
func (c *ResponseHeaders) GetVerificationHeader() *ResponseVerificationHeader {
	if c != nil {
		return c.verifyHeader
	}

	return nil
}

// SetVerificationHeader sets verification header of the response.
func (c *ResponseHeaders) SetVerificationHeader(v *ResponseVerificationHeader) {
	c.verifyHeader = v
}

func (c *ResponseHeaders) ToMessage(m interface {
	SetMetaHeader(*session.ResponseMetaHeader)
	SetVerifyHeader(*session.ResponseVerificationHeader)
}) {
	m.SetMetaHeader(c.metaHeader.ToGRPCMessage().(*session.ResponseMetaHeader))
	m.SetVerifyHeader(c.verifyHeader.ToGRPCMessage().(*session.ResponseVerificationHeader))
}

func (c *ResponseHeaders) FromMessage(m interface {
	GetMetaHeader() *session.ResponseMetaHeader
	GetVerifyHeader() *session.ResponseVerificationHeader
}) error {
	metaHdr := m.GetMetaHeader()
	if metaHdr == nil {
		c.metaHeader = nil
	} else {
		if c.metaHeader == nil {
			c.metaHeader = new(ResponseMetaHeader)
		}

		err := c.metaHeader.FromGRPCMessage(metaHdr)
		if err != nil {
			return err
		}
	}

	verifyHdr := m.GetVerifyHeader()
	if verifyHdr == nil {
		c.verifyHeader = nil
	} else {
		if c.verifyHeader == nil {
			c.verifyHeader = new(ResponseVerificationHeader)
		}

		err := c.verifyHeader.FromGRPCMessage(verifyHdr)
		if err != nil {
			return err
		}
	}

	return nil
}
