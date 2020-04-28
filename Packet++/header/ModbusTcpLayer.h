#ifndef PACKETPP_MODBUSTCP_LAYER
#define PACKETPP_MODBUSTCP_LAYER

#include "Layer.h"
#include <vector>

namespace pcpp
{
#pragma pack(push, 1)

  struct ModbusTcpHeader {
    uint16_t transactionId;
    uint16_t protocolId;
    uint16_t length;
    uint8_t unitId;
    uint8_t functionCode;
    /* function code-specific data goes here */
  };

#pragma pack(pop)

  enum ModbusFnCode {
    MODBUS_FNCODE_READ_COILS = 1,
    MODBUS_FNCODE_READ_DISCRETE_INPUTS = 2,
    MODBUS_FNCODE_READ_HOLDING_REGISTERS = 3,
    /* TODO: the rest */
  };

  /*
   * Even for the same function code, the data format varies depending on the
   * direction [client --(request)--> server] or [server --(response)--> client]
   */
  enum ModbusFnDirection {
    MODBUS_FNDIR_NULL,
    MODBUS_FNDIR_REQUEST,
    MODBUS_FNDIR_RESPONSE,
  };

  /*
   * Abstract base class that represents the data contained in a MODBUS PDU.
   * All specific data structures (read coils, read discrete inputs) are derived
   * from this ABC.
   */
  class ModbusFn {
  public:
    virtual ~ModbusFn() {}
    virtual bool fromBuffer(uint8_t const *buffer, size_t len) = 0;
    virtual size_t toBuffer(uint8_t *buffer) const = 0;
    virtual std::string toString() const = 0;
    virtual size_t requiredLen() const = 0;
  };

  /*
   * The following class represents the parsed value of the Modbus Read Coils
   * request [client --(request)--> server]
   */
  class ModbusFnReadCoilsRequest : public ModbusFn {
  private:
    uint16_t m_StartingAddress;
    unsigned int m_NumCoils;

  public:
    ModbusFnReadCoilsRequest () : ModbusFn() {
      m_StartingAddress = 0;
      m_NumCoils = 0;
    }
    ModbusFnReadCoilsRequest(ModbusFnReadCoilsRequest const &);
    ~ModbusFnReadCoilsRequest() {}
    ModbusFnReadCoilsRequest & operator=(ModbusFnReadCoilsRequest const &);
    
    void startingAddress (uint16_t sa);
    void numCoils (unsigned int nc);
    bool fromBuffer(uint8_t const *buffer, size_t len);
    size_t toBuffer(uint8_t *buffer) const;
    std::string toString() const;
    size_t requiredLen() const;
  };

  /*
   * Response to the above, [server --(response)--> client]
   *
   * Note that the bit positions are relative to the startingAddress in
   * the corresponding Request. For proper/useful decoding, we need a
   * context structure that is maintained/updated across packets that
   * keeps track of the connection + transactionid.
   */
  class ModbusFnReadCoilsResponse : public ModbusFn {
  private:
    /*
     * status (true = ON, false = OFF)
     */
    std::vector<bool> m_CoilStatus;

  public:
    ModbusFnReadCoilsResponse (): ModbusFn(), m_CoilStatus() {
    }
    ModbusFnReadCoilsResponse(ModbusFnReadCoilsResponse const &);
    ~ModbusFnReadCoilsResponse() {};
    ModbusFnReadCoilsResponse & operator=(ModbusFnReadCoilsResponse const &);

    void setNumStatuses(size_t);
    size_t getNumStatuses() const { return m_CoilStatus.size(); }
    bool getStatus(unsigned bp) const { return m_CoilStatus[bp]; }
    void setStatus(unsigned bp, bool val);
    bool fromBuffer(uint8_t const *buffer, size_t len);
    size_t toBuffer(uint8_t *buffer) const;
    std::string toString() const;
    size_t requiredLen() const;
  };

  /*
   * TODO: ModbusFnReadCoilsException
   */

  /*
   * The MODBUS layer, representing a single MODBUS 
   * {function code + associated data}
   * 
   * A single TCP packet may contain multiple MODBUS messages, and these
   * will be represented by multiple ModbusTcpLayers one after the other.
   */
  class ModbusTcpLayer : public Layer {
  public:
    static bool isModbusPort(uint16_t port);

    ModbusTcpLayer(enum ModbusFnDirection dir, uint8_t *data, size_t len,
		   Layer *prevLayer, Packet *packet);
    ModbusTcpLayer();
    ModbusTcpLayer(ModbusTcpLayer const &other);
    ~ModbusTcpLayer();
    ModbusTcpLayer & operator=(ModbusTcpLayer const &other);

    ModbusTcpHeader *getModbusTcpHeader() {
      return (ModbusTcpHeader *) m_Data;
    }

    // const version of above
    ModbusTcpHeader const *getModbusTcpHeaderRo() const {
      return (ModbusTcpHeader const *) m_Data;
    }

    ModbusFn *getFn() {
      return m_Fn;
    }

    // Need this when crafting a layer from scratch
    void setDirection(enum ModbusFnDirection);

    void setFn(ModbusFn *newFn);

    void parseNextLayer();
    size_t getHeaderLen() const;
    void computeCalculateFields();
    std::string toString() const;

    OsiModelLayer getOsiModelLayer() const {
      return OsiModelApplicationLayer;
    }

  private:
    ModbusFn *m_Fn;
    enum ModbusFnDirection m_Direction;
  };
}

#endif
