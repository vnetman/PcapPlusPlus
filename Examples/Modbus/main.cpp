#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <getopt.h>
#include "Logger.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "ModbusTcpLayer.h"

using namespace std;
using namespace pcpp;

#define EXIT_WITH_ERROR(prefix, ...) do { \
  fprintf(stderr, "\n" prefix "\n", ## __VA_ARGS__); \
  exit(-1); \
} while (0);

static void dumpPcapPackets (PcapFileReaderDevice *pcapReader) {
  unsigned count = 0;
  RawPacket rawPacket;
  
  while (pcapReader->getNextPacket(rawPacket)) {
    count++;
    Packet parsedPacket(&rawPacket);

    cout << "***********" << " Packet #" << count << " ***********" << endl;
    cout << parsedPacket.toString() << endl;
  }
  
  cout << count << " packets in pcap" << endl;
}

static void
fabricateModbusPacket (PcapFileWriterDevice *pcapWriter) {
  EthLayer el(MacAddress("00:50:43:11:22:33"), MacAddress("aa:bb:cc:dd:ee"));

  IPv4Layer ipl(IPv4Address(std::string("192.168.1.1")),
		IPv4Address(std::string("10.0.0.1")));
  ipl.getIPv4Header()->ipId = htobe16(2000);
  ipl.getIPv4Header()->timeToLive = 64;

  // create a new TCP layer
  // We're making a MODBUS Read Coils Response packet, so use 502 as the
  // source port.
  TcpLayer tcpl(502, 16385);
  tcpl.getTcpHeader()->sequenceNumber = be32toh(0x12345678);
  tcpl.getTcpHeader()->ackNumber = be32toh(0x9abcdef0);
  tcpl.getTcpHeader()->pshFlag = 1;
  tcpl.getTcpHeader()->ackFlag = 1;

  // Just to keep things interesting, we'll create *TWO* MODBUS layers, both
  // carrying a Read Coils Response.
  ModbusTcpLayer mtl1;
  mtl1.getModbusTcpHeader()->transactionId = 0x7777;
  mtl1.getModbusTcpHeader()->protocolId = 0;
  mtl1.getModbusTcpHeader()->length = 0; //  computeCalculateFields will fix
  mtl1.getModbusTcpHeader()->unitId = 0xff;
  mtl1.getModbusTcpHeader()->functionCode = (uint8_t) MODBUS_FNCODE_READ_COILS;
  mtl1.setDirection(MODBUS_FNDIR_RESPONSE);

  // Create a new MODBUS function body for the response
  ModbusFnReadCoilsResponse *respFn1 = new ModbusFnReadCoilsResponse();
  respFn1->setNumStatuses(20);
  for (unsigned i = 0; i < 20; i++) {
    respFn1->setStatus(i, (i % 2) == 0);
  }

  // Add the function body to the layer
  mtl1.setFn(respFn1);

  ModbusTcpLayer mtl2;
  mtl2.getModbusTcpHeader()->transactionId = 0x6666;
  mtl2.getModbusTcpHeader()->protocolId = 0;
  mtl2.getModbusTcpHeader()->length = 0; //  computeCalculateFields will fix
  mtl2.getModbusTcpHeader()->unitId = 0xff;
  mtl2.getModbusTcpHeader()->functionCode = (uint8_t) MODBUS_FNCODE_READ_COILS;
  mtl2.setDirection(MODBUS_FNDIR_RESPONSE);
  
  // Create a new MODBUS function body for the response
  ModbusFnReadCoilsResponse *respFn2 = new ModbusFnReadCoilsResponse();
  respFn2->setNumStatuses(20);
  for (unsigned i = 0; i < 20; i++) {
    respFn2->setStatus(i, (i % 2) != 0);
  }
  
  // Add the function body to the layer
  mtl2.setFn(respFn2);

  // create a packet with initial capacity of 100 bytes (will grow automatically
  // if needed)
  Packet newPacket(100);

  // add all the layers we created
  newPacket.addLayer(&el);
  newPacket.addLayer(&ipl);
  newPacket.addLayer(&tcpl);
  newPacket.addLayer(&mtl1);
  newPacket.addLayer(&mtl2);

  // compute all calculated fields
  newPacket.computeCalculateFields();

  // Write the edited packet to the PCAP.
  pcapWriter->writePacket(*(newPacket.getRawPacket()));

  cout << "Newly crafted packet saved in output PCAP\n";
}

static void
editFirstModbusRequestAndResponsePackets (PcapFileReaderDevice *pcapReader,
					  PcapFileWriterDevice *pcapWriter) {
  enum ModbusFnCode fnCode;
  unsigned count = 0;
  RawPacket rawPacket;
  ModbusFnReadCoilsRequest *reqFn;
  ModbusFnReadCoilsResponse *respFn;

  // In this function we process one Read Coils request, and one Read Coils
  // response. Keep track of which ones we've finished.
  bool reqFinished = false, respFinished = false;
  
  while (pcapReader->getNextPacket(rawPacket)) {
    if (reqFinished && respFinished) {
      break;
    }

    count++;
    Packet parsedPacket(&rawPacket);

    ModbusTcpLayer *mbl = parsedPacket.getLayerOfType<ModbusTcpLayer>();
    if (!mbl) {
      continue;
    }

    // This version only handles the "Read Coils" function code.
    fnCode = (enum ModbusFnCode) mbl->getModbusTcpHeaderRo()->functionCode;
    if (fnCode != MODBUS_FNCODE_READ_COILS) {
      continue;
    }
    
    reqFn = 0;
    respFn = 0;
    
    // The 'getFn()' method obtains the underlying C++ object that
    // represents the MODBUS Function Data.
    // The dynamic_cast below will return 0 if this not a Request packet,
    // so we depend on that to tell if this is a Request or a Reply.
    reqFn = dynamic_cast<ModbusFnReadCoilsRequest *>(mbl->getFn());
    if (reqFn != 0) {
      // This is a Read Coils Request packet
      if (reqFinished) {
	continue;
      }
      
      // Edit Test: Edit a Read Coils request (change range to 133)
      // First prepare a new function body.
      ModbusFnReadCoilsRequest *newReqFn = new ModbusFnReadCoilsRequest(*reqFn);
      newReqFn->numCoils(133);

      // Replace the existing function body in the layer with the new one we
      // just created. This will have the effect of "editing" the existing
      // layer.
      mbl->setFn(newReqFn);
      parsedPacket.computeCalculateFields();

      // Append test: Add an entirely new Read Coils request
      // This involves adding a second ModbusTcpLayer

      // First make the request function body
      ModbusFnReadCoilsRequest *appendedReqFn = new ModbusFnReadCoilsRequest();
      appendedReqFn->startingAddress(0x1234);
      appendedReqFn->numCoils(266);

      // Next build the layer with some values
      ModbusTcpLayer mtl;
      mtl.getModbusTcpHeader()->transactionId = 0x9999;
      mtl.getModbusTcpHeader()->protocolId = 0;
      mtl.getModbusTcpHeader()->length = 0; //  computeCalculateFields will fix
      mtl.getModbusTcpHeader()->unitId = 0xff;
      mtl.getModbusTcpHeader()->functionCode = (uint8_t) MODBUS_FNCODE_READ_COILS;

      mtl.setDirection(MODBUS_FNDIR_REQUEST);

      // Give the layer the request function body object we made earlier
      mtl.setFn(appendedReqFn);

      // Add the new layer to the existing packet. This will have the effect
      // of appending a new MODBUS Read Coils Request to the TCP payload.
      parsedPacket.addLayer(&mtl);
      parsedPacket.computeCalculateFields();

      // Write this to the PCAP as well. Note that we did not change the
      // IPv4 ID or the TCP sequence number w.r.t. the packet we wrote earlier.
      pcapWriter->writePacket(*(parsedPacket.getRawPacket()));

      reqFinished = true;
      cout << "Request packet #" << count << " edited and saved in " <<
	"output PCAP\n";
    } else {
      respFn = dynamic_cast<ModbusFnReadCoilsResponse *>(mbl->getFn());
      if (respFn != 0) {
	if (respFinished) {
	  continue;
	}

	// Create a new MODBUS function body for the response
	ModbusFnReadCoilsResponse *newRespFn =
	  new ModbusFnReadCoilsResponse(*respFn);

	// Flip all the status bits
	for (unsigned i = 0; i < newRespFn->getNumStatuses(); i++) {
	  newRespFn->setStatus(i, !newRespFn->getStatus(i));
	}

	// Replace the current function body with the one we created above.
	// This will have the effect of editing the MODBUS function body.
	mbl->setFn(newRespFn);
	
	parsedPacket.computeCalculateFields();
	pcapWriter->writePacket(*(parsedPacket.getRawPacket()));

	respFinished = true;
	cout << "Response packet #" << count << " edited and saved in " <<
	  "output PCAP\n";
      }
    }
  }
}

static void usage () {
  char const *msg = "This program takes one PCAP as input and produces two "
    "PCAPs as output.\n"
    "The program prints out summary information for all packets in the input\n"
    "PCAP, including MODBUS headers (only the \"Read Coils\" function "
    "code is\n"
    "currently supported).\n"
    "\n"
    "The program then picks up the first MODBUS Read Coils Request packet "
    "from\n"
    "the input PCAP and edits it by changing some fields, as well as "
    "adding a\n"
    "second Read Coils Request to the same packet. This edited packet "
    "is then\n"
    "written to an output PCAP. Similarly, it picks up the first MODBUS Read\n"
    "Coils Response packet from the input PCAP and edits that as well by \n"
    "changing some fields. This edited packet is also written to the same "
    "output\n"
    "PCAP.\n"
    "\n"
    "Finally, the program crafts a completely new MODBUS Read Coils "
    "Response \n"
    "packet \"from scratch\" and writes that to the second output PCAP.\n\n"
    "Usage: <program> <input pcap> <output pcap 1> <output pcap 2>\n\n";

  std::cout << msg;
}

int main (int argc, char* argv[])
{
  if (argc != 4) {
    usage();
    return -1;
  }
  
  LoggerPP::getInstance().setLogLevel(PacketLogModuleModbusTcpLayer,
				      LoggerPP::Debug);

  IFileReaderDevice *reader;
  PcapFileReaderDevice *pcapReader;
  PcapFileWriterDevice *pcapWriter1, *pcapWriter2;
  
  //---------------------------------------------------------------------------
  // Demo 1: Print packets in a PCAP

  reader = IFileReaderDevice::getReader(argv[1]);
  if (!reader->open()) {
    EXIT_WITH_ERROR("Failed to open input PCAP file %s", argv[1]);
  }
  
  pcapReader = dynamic_cast<PcapFileReaderDevice *>(reader);
  if (!pcapReader) {
    reader->close();
    EXIT_WITH_ERROR("%s is probably not a proper PCAP file", argv[1]);
  }
  
  dumpPcapPackets(pcapReader);

  pcapReader->close();
  reader->close();

  //---------------------------------------------------------------------------
  // Demo 2: Edit MODBUS packets and write result to output PCAP 1

  reader = IFileReaderDevice::getReader(argv[1]);
  if (!reader->open()) {
    EXIT_WITH_ERROR("Failed to open input PCAP file %s", argv[1]);
  }
  
  pcapReader = dynamic_cast<PcapFileReaderDevice *>(reader);
  if (!pcapReader) {
    reader->close();
    EXIT_WITH_ERROR("%s is probably not a proper PCAP file", argv[1]);
  }

  pcapWriter1 = new PcapFileWriterDevice(argv[2]);
  if (!pcapWriter1 || !pcapWriter1->open()) {
    pcapReader->close();
    reader->close();
    EXIT_WITH_ERROR("Failed to open %s for writing", argv[2]);
  }
  
  editFirstModbusRequestAndResponsePackets(pcapReader, pcapWriter1);

  pcapWriter1->close();
  pcapReader->close();
  reader->close();

  //---------------------------------------------------------------------------
  // Demo 3: Create MODBUS packet from scratch
  pcapWriter2 = new PcapFileWriterDevice(argv[3]);
  if (!pcapWriter2 || !pcapWriter2->open()) {
    EXIT_WITH_ERROR("Failed to open %s for writing", argv[3]);
  }
  
  fabricateModbusPacket(pcapWriter2);
  
  pcapWriter2->close();
  //---------------------------------------------------------------------------

  return 0;
}
