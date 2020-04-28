#define LOG_MODULE PacketLogModuleModbusTcpLayer

#include <string.h>
#include <sstream>
#include "ModbusTcpLayer.h"
#include "Logger.h"

namespace pcpp {

  /* static member invoked from TcpLayer.cpp */
  bool ModbusTcpLayer::isModbusPort (uint16_t port) {
    return port == 502;
  }
  
  ModbusTcpLayer::ModbusTcpLayer (enum ModbusFnDirection dir, uint8_t *data,
				  size_t len, Layer *prevLayer, Packet *packet)
    : Layer(data, len, prevLayer, packet) {

    m_Direction = dir;

    switch ((enum ModbusFnCode) getModbusTcpHeaderRo()->functionCode) {
    case MODBUS_FNCODE_READ_COILS:
      if (m_Direction == MODBUS_FNDIR_REQUEST) {
	m_Fn = new ModbusFnReadCoilsRequest;
      } else if (m_Direction == MODBUS_FNDIR_RESPONSE) {
	m_Fn = new ModbusFnReadCoilsResponse;
      } else {
	// Handle error somehow.
	// Until then we crash.
	m_Fn = 0;
      }
      m_Fn->fromBuffer(data + sizeof(struct ModbusTcpHeader),
		       len - sizeof(struct ModbusTcpHeader));
      break;

    default:
      // Handle not-yet-supported function codes appropriately.
      // Maybe we should make a catch-all fake fn object instead of a null.
      m_Fn = 0;
      break;
    }
  }

  ModbusTcpLayer::ModbusTcpLayer () : Layer() {
    m_DataLen = sizeof(struct ModbusTcpHeader);
    m_Data = new uint8_t[m_DataLen];
    memset(m_Data, 0, m_DataLen);

    m_Direction = MODBUS_FNDIR_NULL;
    m_Fn = 0;
  }

  ModbusTcpLayer::ModbusTcpLayer (ModbusTcpLayer const &other) : Layer(other) {
    LOG_ERROR("ModbusTcpLayer copy constructor not implemented yet");
  }

  ModbusTcpLayer::~ModbusTcpLayer () {
    if (m_Fn != 0) {
      delete m_Fn;
      m_Fn = 0;
    }
  }

  ModbusTcpLayer & ModbusTcpLayer::operator= (ModbusTcpLayer const &other) {
    LOG_ERROR("ModbusTcpLayer = operator not implemented yet");
    return *this;
  }

  void ModbusTcpLayer::setDirection (enum ModbusFnDirection dir) {
    if (m_Direction != MODBUS_FNDIR_NULL) {
      LOG_ERROR("Something suspicious: why are we setting direction?");
    }
    m_Direction = dir;
  }

  void ModbusTcpLayer::setFn (ModbusFn *newFn) {
    if (m_Fn != 0) {
      /*
       * Shrink the layer. We could optimize things here if the new 
       * incoming layer is also of the same size as the one that we're now
       * removing - e.g. for the (probably) common case where just a couple
       * of bits are being flipped.
       */
      shortenLayer(sizeof(struct ModbusTcpHeader), m_Fn->requiredLen());
      delete m_Fn;
      m_Fn = 0;
      computeCalculateFields();
    }

    m_Fn = newFn;
    if (m_Fn != 0) {
      computeCalculateFields();
      extendLayer(sizeof(struct ModbusTcpHeader), m_Fn->requiredLen());
      /*
       * Now actually write the new content into the area we allocated
       */
      m_Fn->toBuffer(m_Data + sizeof(struct ModbusTcpHeader));
    }
  }
  
  void ModbusTcpLayer::parseNextLayer () {
    size_t thisLayerLen = getHeaderLen();
    if (m_DataLen <= thisLayerLen) {
      // there's not enough room for another layer
      m_NextLayer = 0;
      return;
    }

    // The next MODBUS message becomes the next layer.
    // Direction (request/response) has to be the same as that of this layer
    // (can't mix requests and responses in same message).
    m_NextLayer = new ModbusTcpLayer(m_Direction, m_Data + thisLayerLen,
				     m_DataLen - thisLayerLen, this, m_Packet);
  }
  
  size_t ModbusTcpLayer::getHeaderLen () const {
    
    // uint16_t transactionId;       ^
    // uint16_t protocolId;          |
    // uint16_t length;              | sizeof(struct ModbusTcpHeader)
    // uint8_t unitId;               |
    // uint8_t functionCode;         v
    // function code-specific data   = m_Fn->requiredLen() 

    uint16_t lenFieldInModbusHeader = be16toh(getModbusTcpHeaderRo()->length);
    size_t headerLen = (sizeof(struct ModbusTcpHeader) - 2) +
      lenFieldInModbusHeader;

    // This is a good time to verify that the fn's required length matches the
    // declared length
    if (m_Fn != 0) {
      if (lenFieldInModbusHeader != (m_Fn->requiredLen() + 2)) {
	LOG_ERROR("Major FU happened; lenFieldInModbusHeader = %u, "
		  "requiredLen = %u", (unsigned) lenFieldInModbusHeader,
		  (unsigned) m_Fn->requiredLen());
      }
    }
    return headerLen;
  }
  
  void ModbusTcpLayer::computeCalculateFields () {
    ModbusTcpHeader *mh = getModbusTcpHeader();
    if (m_Fn != 0) {
      mh->length = htobe16(m_Fn->requiredLen() + 2);
    } else {
      mh->length = htobe16(2);
    }
  }
  
  std::string ModbusTcpLayer::toString () const {
    char repStr[64 + 1];
    ModbusTcpHeader const *hdr = getModbusTcpHeaderRo();
    
    repStr[64] = '\0';
    snprintf(repStr, 64, "modbus %s (t = 0x%04x, p = %u, l = %u, u = %u)",
	     (m_Direction == MODBUS_FNDIR_REQUEST) ? "request" :
	     ((m_Direction == MODBUS_FNDIR_RESPONSE) ? "response" : "???"),
	     be16toh(hdr->transactionId),
	     (unsigned) be16toh(hdr->protocolId),
	     (unsigned) be16toh(hdr->length),
	     (unsigned) hdr->unitId);
	     
    return std::string(repStr) + (m_Fn ? m_Fn->toString() : "(fn not handled)");
  }

  //---------------------------------------------------------------------------

  ModbusFnReadCoilsRequest::ModbusFnReadCoilsRequest (ModbusFnReadCoilsRequest
						      const &other) {
    m_StartingAddress = other.m_StartingAddress;
    m_NumCoils = other.m_NumCoils;
  }
  
  ModbusFnReadCoilsRequest &
  ModbusFnReadCoilsRequest::operator= (ModbusFnReadCoilsRequest const &other) {
    m_StartingAddress = other.m_StartingAddress;
    m_NumCoils = other.m_NumCoils;
    return *this;
  }
  
  void ModbusFnReadCoilsRequest::startingAddress (uint16_t sa) {
    m_StartingAddress = sa;
  }
  
  void ModbusFnReadCoilsRequest::numCoils (unsigned int nc) {
    m_NumCoils = nc;
  }
  
  bool ModbusFnReadCoilsRequest::fromBuffer (uint8_t const *buffer, size_t len) {
    m_StartingAddress = be16toh(*((uint16_t *) &buffer[0]));
    m_NumCoils = be16toh(*((uint16_t *) &buffer[2]));
    return true;
  }
  
  size_t ModbusFnReadCoilsRequest::toBuffer (uint8_t *buffer) const {
    *((uint16_t *) &buffer[0]) = htobe16(m_StartingAddress);
    *((uint16_t *) &buffer[2]) = htobe16(m_NumCoils);
    return 4;
  }
  
  std::string ModbusFnReadCoilsRequest::toString() const {
    char repString[64 + 1];
    repString[64] = '\0';
    snprintf(repString, 64, "read coils (start = 0x%04x, num = %u)",
	     m_StartingAddress, (unsigned) m_NumCoils);
    return std::string(repString);
  }
  
  size_t ModbusFnReadCoilsRequest::requiredLen() const {
    return 4;
  }

  //-----------------------------------------------------------------------------

  ModbusFnReadCoilsResponse::ModbusFnReadCoilsResponse (ModbusFnReadCoilsResponse
							const &other) {
    m_CoilStatus = other.m_CoilStatus;
  }
  
  ModbusFnReadCoilsResponse &
  ModbusFnReadCoilsResponse::operator= (ModbusFnReadCoilsResponse const & other) {
    m_CoilStatus = other.m_CoilStatus;
    return *this;
  }
  
  void ModbusFnReadCoilsResponse::setStatus (unsigned bp, bool val) {
    m_CoilStatus[bp] = val;
  }

  void ModbusFnReadCoilsResponse::setNumStatuses (size_t count) {
    m_CoilStatus.resize(count);
    for (unsigned i = 0; i < count; i++) {
      setStatus(i, false);
    }
  }

  bool ModbusFnReadCoilsResponse::fromBuffer (uint8_t const *buffer,
					      size_t len) {
    // First byte = num of bytes to follow
    size_t numStatusBytes = (size_t) *buffer;
    m_CoilStatus.resize(numStatusBytes * 8);
    
    unsigned coilIndex = 0;
    for (unsigned index = 0; index < numStatusBytes; index++) {
      uint8_t candidateByte = *(buffer + 1 + index);
      uint8_t mask = 0x1;
      for (unsigned bitCount = 0; bitCount < 8; bitCount++) {
	if ((candidateByte & mask) == (uint8_t) 0) {
	  m_CoilStatus[coilIndex] = false;
	} else {
	  m_CoilStatus[coilIndex] = true;
	}
	mask <<= 1;
	coilIndex++;
      }
    }
    return true;
  }
  
  size_t ModbusFnReadCoilsResponse::toBuffer (uint8_t *buffer) const {
    size_t numCoilsMax = m_CoilStatus.size();
    size_t numStatusBytes = (numCoilsMax + 7) / 8;
    
    // First byte = num of bytes to follow
    *buffer = (uint8_t) numStatusBytes;

    unsigned coilIndex = 0;
    for (unsigned index = 0; index < numStatusBytes; index++) {
      uint8_t candidateByte = 0;
      uint8_t mask = 0x1;
      for (unsigned bitCount = 0; bitCount < 8; bitCount++) {
	if (m_CoilStatus[coilIndex]) {
	  candidateByte |= mask;
	}
	coilIndex++;
	mask <<= 1;
      }
      *(buffer + 1 + index) = candidateByte;
    }
    return numStatusBytes + 1;
  }

  std::string ModbusFnReadCoilsResponse::toString() const {
    return "read coils response";
  }
  
  size_t ModbusFnReadCoilsResponse::requiredLen() const {
    size_t numCoilsMax = m_CoilStatus.size();
    size_t numStatusBytes = (numCoilsMax + 7) / 8;
    return numStatusBytes + 1;
  }
  
} // namespace pcpp
