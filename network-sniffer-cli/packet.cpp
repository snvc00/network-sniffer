#include "packet.h"

Packet::Packet()
{
}

Packet::~Packet()
{
}

unsigned int Packet::BinaryToInteger_256bits(const unsigned int _initBit, const unsigned int _endBit, std::vector<unsigned char>& _packetArrayBits) const
{
	std::string byte;

	for (unsigned int i(_initBit); i < _endBit; ++i)
		byte.push_back(_packetArrayBits[i]);

	return static_cast<unsigned int>(std::bitset<256>(byte).to_ulong());
}

unsigned char Packet::ByteToChar(const unsigned int byte_position, std::vector<unsigned char>& _packetArrayBytes) const
{
	return static_cast<unsigned char>(_packetArrayBytes[byte_position]);
}

void Packet::Ethernet(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [Ethernet]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	std::cout << " Destination MAC: ";
	for (int i = 0; i < DESTINATION_ADRESS_LIMIT; ++i) {
		if (i == 0)
			printf("%02X", _packetArrayBytes[i]);
		else
			printf(":%02X", _packetArrayBytes[i]);
	}
	
	std::cout << "\n Source MAC: ";
	for (int i = DESTINATION_ADRESS_LIMIT; i < SOURCE_ADRESS_LIMIT; ++i) {
		if (i == DESTINATION_ADRESS_LIMIT)
			printf("%02X", _packetArrayBytes[i]);
		else
			printf(":%02X", _packetArrayBytes[i]);
	}

	unsigned int type = _packetArrayBytes[TYPE_BYTE_1] + _packetArrayBytes[TYPE_BYTE_2];

	switch (type)
	{
	case TYPE_IPV4:
		std::cout << "\n Type: IPv4\n";
		std::cout << " Data size: " << _packetArrayBytes.size() - MAC_AND_TYPE_BYTES << " bytes\n\n";
		IPv4(_packetArrayBytes, _packetArrayBits);
		system("pause");
		break;
	case TYPE_IPV6:
		std::cout << "\n Type: IPv6\n";
		std::cout << " Data size: " << _packetArrayBytes.size() - MAC_AND_TYPE_BYTES << " bytes\n\n";
		IPv6(_packetArrayBytes, _packetArrayBits);
		system("pause");
		break;
	case TYPE_ARP:
		std::cout << "\n Type: ARP\n";
		std::cout << " Data size: " << _packetArrayBytes.size() - MAC_AND_TYPE_BYTES << " bytes\n\n";
		ARP_RARP(_packetArrayBytes, _packetArrayBits);
		system("pause");
		break;
	case TYPE_RARP:
		std::cout << "\n Type: RARP\n";
		std::cout << " Data size: " << _packetArrayBytes.size() - MAC_AND_TYPE_BYTES << " bytes\n\n";
		ARP_RARP(_packetArrayBytes, _packetArrayBits);
		system("pause");
		break;
	default:
		std::cout << type;
		SetConsoleTextAttribute(STDOUT_HANDLE, 6);
		std::cout << "\n\n WARNING: Undefined type (Not IPv4, IPv6, ARP or RARP)\n";
		std::cin.get();
		SetConsoleTextAttribute(STDOUT_HANDLE, 7);
		break;
	}
}

void Packet::IPv4(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int version, headerLength, typeOfService[IPV4_TYPE_OF_SERVICE_BYTES], totalLength, identifier, flags[IPV4_FLAGS_BYTES];
	unsigned int fragmentOffset, timeToLive, protocol, sourceAddress[IPV4_ADDRESS_BYTES], destinationAddress[IPV4_ADDRESS_BYTES];

	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [IPv4]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	version = BinaryToInteger_256bits(IPV4_VERSION_BEGIN, IPV4_VERSION_END, _packetArrayBits);
	if (version == IPV4)
		std::cout << " Version: IPv4\n";
	else if (version == IPV6)
		std::cout << " Version: IPv6\n";

	headerLength = BinaryToInteger_256bits(IPV4_HEADER_LENGTH_BEGIN, IPV4_HEADER_LENGTH_END, _packetArrayBits);
	std::cout << " Header length: " << headerLength << " words\n";

	// Type of Service
	std::cout << " (Type of Service)-----------------\n";

	typeOfService[IPV4_TOS_PRECEDENCE] = BinaryToInteger_256bits(IPV4_TOS_PRECEDENCE_BEGIN, IPV4_TOS_PRECEDENCE_END, _packetArrayBits);
	typeOfService[IPV4_TOS_DELAY] = BinaryToInteger_256bits(IPV4_TOS_DELAY_BEGIN, IPV4_TOS_DELAY_END, _packetArrayBits);
	typeOfService[IPV4_TOS_THROUGHPUT] = BinaryToInteger_256bits(IPV4_TOS_THROUGHPUT_BEGIN, IPV4_TOS_THROUGHPUT_END, _packetArrayBits);
	typeOfService[IPV4_TOS_RELIABILITY] = BinaryToInteger_256bits(IPV4_TOS_RELIABILITY_BEGIN, IPV4_TOS_RELIABILITY_END, _packetArrayBits);
	typeOfService[IPV4_TOS_MONETARY_COST] = BinaryToInteger_256bits(IPV4_TOS_MONETARY_COST_BEGIN, IPV4_TOS_MONETARY_COST_END, _packetArrayBits);

	// TOS*Precedence*
	switch (typeOfService[IPV4_TOS_PRECEDENCE])
	{
	case IPV4_TOS_PRECEDENCE_ROUTINE:
		std::cout << " Precedence: Routine\n";
		break;
	case IPV4_TOS_PRECEDENCE_PRIORITY:
		std::cout << " Precedence: Priority\n";
		break; 
	case IPV4_TOS_PRECEDENCE_INMEDIATE:
		std::cout << " Precedence: Inmediate\n";
		break;
	case IPV4_TOS_PRECEDENCE_FLASH:
		std::cout << " Precedence: Flash\n";
		break;
	case IPV4_TOS_PRECEDENCE_FLASH_OVERRIDE:
		std::cout << " Precendecia: Flash Override\n";
		break;
	case IPV4_TOS_PRECEDENCE_CRITIC:
		std::cout << " Precedence: Critic\n";
		break;
	case IPV4_TOS_PRECEDENCE_INTERNETWORK_CONTROL:
		std::cout << " Precedence: Internetwork Control\n";
		break;
	case IPV4_TOS_PRECEDENCE_NETWORK_CONTROL:
		std::cout << " Precedence: Network Control\n";
		break;
	default:
		std::cout << " Precedence: Not specified\n";
		break;
	}

	// TOS*Delay*
	if (typeOfService[IPV4_TOS_DELAY] == IPV4_TOS_DELAY_NORMAL)
		std::cout << " Delay: Normal\n";
	else if (typeOfService[IPV4_TOS_DELAY] == IPV4_TOS_DELAY_MINIMIZE)
		std::cout << " Delay: Minimize\n";
	else
		std::cout << " Delay: Not specified\n";

	// TOS*Throughput*
	if (typeOfService[IPV4_TOS_THROUGHPUT] == IPV4_TOS_THROUGHPUT_NORMAL)
		std::cout << " Throughput: Normal\n";
	else if (typeOfService[IPV4_TOS_THROUGHPUT] == IPV4_TOS_THROUGHPUT_MAXIMIZE)
		std::cout << " Throughput: Maximize\n";
	else
		std::cout << " Throughput: Not specified\n";

	// TOS*Reliability*
	if (typeOfService[IPV4_TOS_RELIABILITY] == IPV4_TOS_RELIABILITY_NORMAL)
		std::cout << " Reliability: Normal\n";
	else if (typeOfService[IPV4_TOS_RELIABILITY] == IPV4_TOS_RELIABILITY_MAXIMIZE)
		std::cout << " Reliability: Maximize\n";
	else
		std::cout << " Reliability: Not specified\n";

	// TOS*Monetary Cost*
	if (typeOfService[IPV4_TOS_MONETARY_COST] == IPV4_TOS_MONETARYCOST_NORMAL)
		std::cout << " Monetary Cost: Normal\n";
	else if (typeOfService[IPV4_TOS_MONETARY_COST] == IPV4_TOS_MONETARYCOST_MINIMIZE)
		std::cout << " Monetary Cost: Minimize\n";
	else
		std::cout << " Monetary Cost: Not specified\n";
	std::cout << " -----------------------------------\n";

	// Total length
	totalLength = BinaryToInteger_256bits(IPV4_TOTAL_LENGTH_BEGIN, IPV4_TOTAL_LENGTH_END, _packetArrayBits);
	std::cout << " Total length: " << totalLength << " bytes\n";

	// Identifier
	identifier = BinaryToInteger_256bits(IPV4_IDENTIFIER_BEGIN, IPV4_IDENTIFIER_END, _packetArrayBits);
	std::cout << " Identifier: " << identifier << std::endl;

	// Flags
	flags[IPV4_FLAG_IS_DIVIDED_BYTE] = BinaryToInteger_256bits(IPV4_FLAG_0_BEGIN, IPV4_FLAG_0_END, _packetArrayBits);
	flags[IPV4_FLAG_LAST_FRAGMENT_BYTE] = BinaryToInteger_256bits(IPV4_FLAG_1_BEGIN, IPV4_FLAG_1_END, _packetArrayBits);

	if (flags[IPV4_FLAG_IS_DIVIDED_BYTE] == IPV4_FLAG_DIVIDED)
		std::cout << " Divided packet: Yes\n";
	else if (flags[IPV4_FLAG_IS_DIVIDED_BYTE] == IPV4_FLAG_NOT_DIVIDED)
		std::cout << " Divided packet: No\n";
	else
		std::cout << " Divided packet: Not specified\n";

	if (flags[IPV4_FLAG_LAST_FRAGMENT_BYTE] == IPV4_FLAG_LAST_FRAGMENT)
		std::cout << " Last fragment: Yes\n";
	else if (flags[IPV4_FLAG_LAST_FRAGMENT_BYTE] == IPV4_FLAG_NOT_LAST_FRAGMENT)
		std::cout << " Last fragment: No\n";
	else
		std::cout << " Last fragment: Not specified\n";

	// Fragment Offset
	fragmentOffset = BinaryToInteger_256bits(IPV4_FRAGMENT_OFFSET_BEGIN, IPV4_FRAGMENT_OFFSET_END, _packetArrayBits);

	if (fragmentOffset)
		std::cout << " Fragment offset: " << fragmentOffset << std::endl;
	else
		std::cout << " Fragment offset: Fragment not divided\n";

	// Time to Live
	timeToLive = BinaryToInteger_256bits(IPV4_TIME_TO_LIVE_BEGIN, IPV4_TIME_TO_LIVE_END, _packetArrayBits);
	std::cout << " Time to live: " << timeToLive << " remaining jumps\n";

	// Protocol
	protocol = BinaryToInteger_256bits(IPV4_PROTOCOL_BEGIN, IPV4_PROTOCOL_END, _packetArrayBits);

	switch (protocol)
	{
	case IPV4_PROTOCOL_ICMP:
		std::cout << " Protocol: ICMP\n";
		break;
	case IPV4_PROTOCOL_TCP:
		std::cout << " Protocol : TCP\n";
		break;
	case IPV4_PROTOCOL_UDP:
		std::cout << " Protocol: UDP\n";
		break;
	case IPV4_PROTOCOL_STP:
		std::cout << " Protocol: STP\n";
		break;
	case IPV4_PROTOCOL_SMP:
		std::cout << " Protocol: SMP\n";
		break;
	default:
		std::cout << " Protocol: Unknown\n";
		break;
	}

	// Checksum
	std::cout << " Checksum: ";
	printf("%02X", _packetArrayBytes[IPV4_CHECKSUM_BYTE_1]);
	printf(":%02X\n", _packetArrayBytes[IPV4_CHECKSUM_BYTE_2]);

	// Source Address
	sourceAddress[0] = BinaryToInteger_256bits(IPV4_SOURCE_ADDRESS_POS0_BEGIN, IPV4_SOURCE_ADDRESS_POS0_END, _packetArrayBits);
	sourceAddress[1] = BinaryToInteger_256bits(IPV4_SOURCE_ADDRESS_POS1_BEGIN, IPV4_SOURCE_ADDRESS_POS1_END, _packetArrayBits);
	sourceAddress[2] = BinaryToInteger_256bits(IPV4_SOURCE_ADDRESS_POS2_BEGIN, IPV4_SOURCE_ADDRESS_POS2_END, _packetArrayBits);
	sourceAddress[3] = BinaryToInteger_256bits(IPV4_SOURCE_ADDRESS_POS3_BEGIN, IPV4_SOURCE_ADDRESS_POS3_END, _packetArrayBits);
	std::cout << " Source IP Address: " << sourceAddress[0] << "." << sourceAddress[1] << "." << sourceAddress[2] << "." << sourceAddress[3] << "\n";

	// Destination Address
	destinationAddress[0] = BinaryToInteger_256bits(IPV4_DESTINATION_ADDRESS_POS0_BEGIN, IPV4_DESTINATION_ADDRESS_POS0_END, _packetArrayBits);
	destinationAddress[1] = BinaryToInteger_256bits(IPV4_DESTINATION_ADDRESS_POS1_BEGIN, IPV4_DESTINATION_ADDRESS_POS1_END, _packetArrayBits);
	destinationAddress[2] = BinaryToInteger_256bits(IPV4_DESTINATION_ADDRESS_POS2_BEGIN, IPV4_DESTINATION_ADDRESS_POS2_END, _packetArrayBits);
	destinationAddress[3] = BinaryToInteger_256bits(IPV4_DESTINATION_ADDRESS_POS3_BEGIN, IPV4_DESTINATION_ADDRESS_POS3_END, _packetArrayBits);
	std::cout << " Destination IP Address: " << destinationAddress[0] << "." << destinationAddress[1] << "." << destinationAddress[2] << "." << destinationAddress[3] << "\n\n";

	if (protocol == IPV4_PROTOCOL_TCP)
		TCP(FROM_IPV4, protocol, _packetArrayBytes, _packetArrayBits);
	else if (protocol == IPV4_PROTOCOL_ICMP)
		ICMPv4(_packetArrayBytes, _packetArrayBits);
	else if (protocol == IPV4_PROTOCOL_UDP)
		UDP(FROM_IPV4, protocol, _packetArrayBytes, _packetArrayBits);
}

void Packet::ICMPv4(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int type(0), code(0);

	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [ICMPv4]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	// Type
	type = BinaryToInteger_256bits(ICMPV4_TYPE_BEGIN, ICMPV4_TYPE_END, _packetArrayBits);

	switch (type)
	{
	case ICMPV4_TYPE_ECHO_REPLY:
		std::cout << " Type: Echo reply\n";
		break;
	case ICMPV4_TYPE_DESTINATION_UNREACHEABLE:
		std::cout << " Type: Destination unreacheable\n";
		break;
	case ICMPV4_TYPE_SOURCE_QUENCH:
		std::cout << " Type: Source quench\n";
		break;
	case ICMPV4_TYPE_REDIRECT:
		std::cout << " Type: Redirect\n";
		break;
	case ICMPV4_TYPE_ECHO:
		std::cout << " Type: Echo request\n";
		break;
	case ICMPV4_TYPE_TIME_EXCEEDED:
		std::cout << " Type: Time exceeded\n";
		break;
	case ICMPV4_TYPE_PARAMETER_PROBLEM:
		std::cout << " Type: Parameter problem\n";
		break;
	case ICMPV4_TYPE_TIMESTAMP:
		std::cout << " Type: Timestamp request\n";
		break;
	case ICMPV4_TYPE_TIMESTAMP_REPLY:
		std::cout << " Type: Timestamp reply\n";
		break;
	case ICMPV4_TYPE_INFORMATION_REQUEST:
		std::cout << " Type: Information request\n";
		break;
	case ICMPV4_TYPE_INFORMATION_REPLY:
		std::cout << " Type: Information reply\n";
		break;
	case ICMPV4_TYPE_ADDRESSMARK:
		std::cout << " Type: Addressmark request\n";
		break;
	case ICMPV4_TYPE_ADDRESSMARK_REPLY:
		std::cout << " Type: Addressmark reply\n";
		break;
	default:
		std::cout << " Type: Not specified\n";
		break;
	}

	// Code
	code = BinaryToInteger_256bits(ICMPV4_CODE_BEGIN, ICMPV4_CODE_END, _packetArrayBits);

	switch (code)
	{
	case ICMPV4_CODE_0:
		std::cout << " Code: Unreachable network\n";
		break;
	case ICMPV4_CODE_1:
		std::cout << " Code: Unreachable host\n";
		break;
	case ICMPV4_CODE_2:
		std::cout << " Code: Destination does not have selected protocol\n";
		break;
	case ICMPV4_CODE_3:
		std::cout << " Code: Unreachable port\n";
		break;
	case ICMPV4_CODE_4:
		std::cout << " Code: Fragmentation required\n";
		break;
	case ICMPV4_CODE_5:
		std::cout << " Code: Origin path is not correct\n";
		break;
	case ICMPV4_CODE_6:
		std::cout << " Code: Unknown destination network\n";
		break;
	case ICMPV4_CODE_7:
		std::cout << " Code: Unknown destination host\n";
		break;
	case ICMPV4_CODE_8:
		std::cout << " Code: Isolated source host\n";
		break;
	case ICMPV4_CODE_9:
		std::cout << " Code: Destination network is administrative blocked\n";
		break;
	case ICMPV4_CODE_10:
		std::cout << " Code: Destination host is administrative blocked\n";
		break;
	case ICMPV4_CODE_11:
		std::cout << " Code: Type of service makes the destination network unreachable\n";
		break;
	case ICMPV4_CODE_12:
		std::cout << " Code: Type of service makes the destination host unreachable\n";
		break;
	default:
		std::cout << " Code: Not specified\n";
		break;
	}

	// Checksum
	std::cout << " Checksum: ";
	printf("%02X", _packetArrayBytes[ICMPV4_CHECKSUM_BYTE1]);
	printf(":%02X\n", _packetArrayBytes[ICMPV4_CHECKSUM_BYTE2]);

	std::cout << "\n";
}

void Packet::ARP_RARP(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int hardwareType, hardwareAddressLength, protocolAddressLength, opcode;
	unsigned int sourceAddress[IPV4_ADDRESS_BYTES], destinationAddress[IPV4_ADDRESS_BYTES];

	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [ARP/RARP]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	// Hardware type
	hardwareType = BinaryToInteger_256bits(ARP_HARDWARE_TYPE_BEGIN, ARP_HARDWARE_TYPE_END, _packetArrayBits);

	switch (hardwareType)
	{
	case ARP_TOH_RESERVED:
		std::cout << " Hardware type: Reserved\n";
		break;
	case ARP_TOH_ETHERNET_10MB:
		std::cout << " Hardware type: Ethernet (10MB)\n";
		break;
	case ARP_TOH_IEEE_802NETWORKS:
		std::cout << " Hardware type: IEEE 802 Network\n";
		break;
	case ARP_TOH_ARCNET:
		std::cout << " Hardware type: ARCNET\n";
		break;
	case ARP_TOH_FRAME_RELAY:
		std::cout << " Hardware type: Frame Relay\n";
		break;
	case ARP_TOH_ATM:
		std::cout << " Hardware type: ATM\n";
		break;
	case ARP_TOH_HDLC:
		std::cout << " Hardware type: HDLC\n";
		break;
	case ARP_TOH_FIBRE_CHANNEL:
		std::cout << " Hardware type: Fibre Channel\n";
		break;
	case ARP_TOH_SERIAL_LINE:
		std::cout << " Hardware type: Serial Line\n";
		break;
	default:
		std::cout << " Hardware type: Not specified\n";
		break;
	}

	// Protocol Type
	std::cout << " Protocol type: ";
	printf("%02X", _packetArrayBytes[ARP_PROTOCOL_TYPE_BYTE_1]);
	printf(":%02X\n", _packetArrayBytes[ARP_PROTOCOL_TYPE_BYTE_2]);

	// Hardware Adress Length
	hardwareAddressLength = BinaryToInteger_256bits(ARP_HARDWARE_ADDRESS_LENGTH_BEGIN, ARP_HARDWARE_ADDRESS_LENGTH_END, _packetArrayBits);
	std::cout << " Hardware address length: " << hardwareAddressLength << " bytes\n";

	// Protocol Address Length
	protocolAddressLength = BinaryToInteger_256bits(ARP_PROTOCOL_ADDRESS_LENGTH_BEGIN, ARP_PROTOCOL_ADDRESS_LENGTH_END, _packetArrayBits);
	std::cout << " Protocol address length: " << protocolAddressLength << " bytes\n";

	// Optional Code
	opcode = BinaryToInteger_256bits(ARP_OPTIONAL_CODE_BEGIN, ARP_OPTIONAL_CODE_END, _packetArrayBits);

	switch (opcode)
	{
	case ARP_OPCODE_ARP_REQUEST:
		std::cout << " Opcode: ARP request\n";
		break;
	case ARP_OPCODE_ARP_REPLY:
		std::cout << " Opcode: ARP reply\n";
		break;
	case ARP_OPCODE_RARP_REQUEST:
		std::cout << " Opcode: RARP request\n";
		break;
	case ARP_OPCODE_RARP_REPLY:
		std::cout << " Opcode: RARP reply\n";
		break;
	case ARP_OPCODE_DRARP_REQUEST:
		std::cout << " Opcode: DRARP request\n";
		break;
	case ARP_OPCODE_DRARP_REPLY:
		std::cout << " Opcode: DRARP reply\n";
		break;
	case ARP_OPCODE_DRARP_ERROR:
		std::cout << " Opcode: DRARP error\n";
		break;
	case ARP_OPCODE_INARP_REQUEST:
		std::cout << " Opcode: InARP request\n";
		break;
	case ARP_OPCODE_INARP_REPLY:
		std::cout << " Opcode: InARP reply\n";
		break;
	default:
		std::cout << " Opcode: Not specified\n";
		break;
	}

	// Sender Hardware Address
	std::cout << " Sender hardware address: ";
	for (int i = ARP_SENDER_HARDWARE_ADDRESS_BEGIN; i < ARP_SENDER_HARDWARE_ADDRESS_END; ++i)
	{
		if (i == ARP_SENDER_HARDWARE_ADDRESS_BEGIN)
			printf("%02X", _packetArrayBytes[i]);
		else
			printf(":%02X", _packetArrayBytes[i]);
	}
	std::cout << "\n";

	// Sender Protocol Address
	sourceAddress[0] = BinaryToInteger_256bits(ARP_SENDER_PROTOCOL_ADDRESS_FIELD1_BEGIN, ARP_SENDER_PROTOCOL_ADDRESS_FIELD1_END, _packetArrayBits);
	sourceAddress[1] = BinaryToInteger_256bits(ARP_SENDER_PROTOCOL_ADDRESS_FIELD2_BEGIN, ARP_SENDER_PROTOCOL_ADDRESS_FIELD2_END, _packetArrayBits);
	sourceAddress[2] = BinaryToInteger_256bits(ARP_SENDER_PROTOCOL_ADDRESS_FIELD3_BEGIN, ARP_SENDER_PROTOCOL_ADDRESS_FIELD3_END, _packetArrayBits);
	sourceAddress[3] = BinaryToInteger_256bits(ARP_SENDER_PROTOCOL_ADDRESS_FIELD4_BEGIN, ARP_SENDER_PROTOCOL_ADDRESS_FIELD4_END, _packetArrayBits);
	std::cout << " Sender protocol address: " << sourceAddress[0] << "." << sourceAddress[1] << "." << sourceAddress[2] << "." << sourceAddress[3] << "\n";

	// Target Hardware Address
	std::cout << " Target hardware address: ";
	for (int i = ARP_TARGET_HARDWARE_ADDRESS_BEGIN; i < ARP_TARGET_HARDWARE_ADDRESS_END; ++i) {
		if (i == ARP_TARGET_HARDWARE_ADDRESS_BEGIN)
			printf("%02X", _packetArrayBytes[i]);
		else
			printf(":%02X", _packetArrayBytes[i]);
	}
	std::cout << "\n";

	// Target Protocol Address
	destinationAddress[0] = BinaryToInteger_256bits(ARP_TARGET_PROTOCOL_ADDRESS_FIELD1_BEGIN, ARP_TARGET_PROTOCOL_ADDRESS_FIELD1_END, _packetArrayBits);
	destinationAddress[1] = BinaryToInteger_256bits(ARP_TARGET_PROTOCOL_ADDRESS_FIELD2_BEGIN, ARP_TARGET_PROTOCOL_ADDRESS_FIELD2_END, _packetArrayBits);
	destinationAddress[2] = BinaryToInteger_256bits(ARP_TARGET_PROTOCOL_ADDRESS_FIELD3_BEGIN, ARP_TARGET_PROTOCOL_ADDRESS_FIELD3_END, _packetArrayBits);
	destinationAddress[3] = BinaryToInteger_256bits(ARP_TARGET_PROTOCOL_ADDRESS_FIELD4_BEGIN, ARP_TARGET_PROTOCOL_ADDRESS_FIELD4_END, _packetArrayBits);
	std::cout << " Target protocol address: " << destinationAddress[0] << "." << destinationAddress[1] << "." << destinationAddress[2] << "." << destinationAddress[3] << "\n\n";
}

void Packet::IPv6(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int version(0), flowLabbel(0), payloadLength(0), nextHeader(0), hopLimit(0);
	std::string trafficClass;

	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [IPv6]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	//Version
	version = BinaryToInteger_256bits(IPV6_VERSION_BEGIN, IPV6_VERSION_END, _packetArrayBits);
	if (version == IPV6_VERSION_ID)
		std::cout << " Version: IPv6\n";
	else
		std::cout << " Version: Not IPv6\n";

	// Traffic Class
	for (int i = IPV6_TRAFFIC_CLASS_BEGIN; i < IPV6_TRAFFIC_CLASS_END; ++i)
		trafficClass.push_back(_packetArrayBits[i]);
	std::cout << " Traffic class: " << trafficClass << "\n";

	// Flow Labbel
	flowLabbel = BinaryToInteger_256bits(IPV6_FLOW_LABBEL_BEGIN, IPV6_FLOW_LABBEL_END, _packetArrayBits);
	std::cout << " Flow labbel: " << flowLabbel << "\n";

	// Payload Length
	payloadLength = BinaryToInteger_256bits(IPV6_PAYLOAD_LENGTH_BEGIN, IPV6_PAYLOAD_LENGTH_END, _packetArrayBits);
	std::cout << " Payload length: " << payloadLength << " bytes\n";

	// Next Header
	nextHeader = BinaryToInteger_256bits(IPV6_NEXT_HEADER_BEGIN, IPV6_NEXT_HEADER_END, _packetArrayBits);

	switch (nextHeader)
	{
	case IPV6_NEXT_HEADER_TCP:
		std::cout << " Next header: TCP\n";
		break;
	case IPV6_NEXT_HEADER_UDP:
		std::cout << " Next header: UDP\n";
		break;
	case IPV6_NEXT_HEADER_ICMPV6:
		std::cout << " Next header: ICMPv6\n";
		break;
	default:
		std::cout << " Next header: Not specified\n";
		break;
	}

	// Hop Limit
	hopLimit = BinaryToInteger_256bits(IPV6_HOP_LIMIT_BEGIN, IPV6_HOP_LIMIT_END, _packetArrayBits);
	std::cout << " Hop limit: " << hopLimit << " remaining jumps\n";

	// Source Address
	std::cout << " Source address: ";
	for (int i = IPV6_SOURCE_ADDRESS_BEGIN; i < IPV6_SOURCE_ADDRESS_END; ++i) {
		if (i == IPV6_SOURCE_ADDRESS_BEGIN)
			printf("%02X", _packetArrayBytes[i]);
		else 
			printf(":%02X", _packetArrayBytes[i]);
	}
	std::cout << "\n";

	// Destination Address
	std::cout << " Destination address: ";
	for (int i = IPV6_DESTINATION_ADDRESS_BEGIN; i < IPV6_DESTINATION_ADDRESS_END; ++i) {
		if (i == IPV6_DESTINATION_ADDRESS_BEGIN)
			printf("%02X", _packetArrayBytes[i]);
		else
			printf(":%02X", _packetArrayBytes[i]);
	}
	std::cout << "\n\n";

	if (nextHeader == IPV6_NEXT_HEADER_ICMPV6)
		ICMPv6(_packetArrayBytes, _packetArrayBits);
	if (nextHeader == IPV6_NEXT_HEADER_TCP)
		TCP(FROM_IPV6, nextHeader, _packetArrayBytes, _packetArrayBits);
	if (nextHeader == IPV6_NEXT_HEADER_UDP)
		UDP(FROM_IPV6, nextHeader, _packetArrayBytes, _packetArrayBits);
}

void Packet::ICMPv6(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int type, code;

	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [ICMPv6]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	// Type and Code
	type = BinaryToInteger_256bits(ICMPV6_TYPE_BEGIN, ICMPV6_TYPE_END, _packetArrayBits);
	code = BinaryToInteger_256bits(ICMPV6_CODE_BEGIN, ICMPV6_CODE_END, _packetArrayBits);

	switch (type)
	{
	case ICMPV6_TYPE_RESERVED:
		std::cout << " Type: Reserved\nCode: Reserved\n";
		break;
	case ICMPV6_TYPE_DESTINATION_UNREACHABLE:
		std::cout << " Type: Destination message unreachable\n";
		switch (code)
		{
		case ICMPV6_OPTION_DESTINATION_UNREACHABLE_0:
			std::cout << " Code: Destination path does not exist\n";
			break;
		case ICMPV6_OPTION_DESTINATION_UNREACHABLE_1:
			std::cout << " Code: Destination administrative prohibited\n";
			break;
		case ICMPV6_OPTION_DESTINATION_UNREACHABLE_2:
			std::cout << " Code: Not assigned\n";
			break;
		case ICMPV6_OPTION_DESTINATION_UNREACHABLE_3:
			std::cout << " Code: Address unreachable\n";
			break;
		default:
			std::cout << " Code: Not specified\n";
			break;
		}
		break;
	case ICMPV6_TYPE_PACKET_TOO_BIG:
		std::cout << " Type: Packet too big\nCode: Not specified\n";
		break;
	case ICMPV6_TYPE_TIME_EXCEEDED:
		std::cout << " Type: Time exceeded\n";
		if (code == ICMPV6_OPTION_TIME_EXCEEDED_0)
			std::cout << " Code: Hop limit exceeded\n";
		else if (code == ICMPV6_OPTION_TIME_EXCEEDED_1)
			std::cout << " Code: Reassemble time exceeded\n";
		else
			std::cout << " Code: Not specified\n";
		break;
	case ICMPV6_TYPE_PARAMETER_PROBLEM:
		std::cout << " Type: Parameter problem\n";
		switch (code)
		{
		case ICMPV6_OPTION_PARAMETER_PROBLEM_0:
			std::cout << " Option: Wrong header field\n";
			break;
		case ICMPV6_OPTION_PARAMETER_PROBLEM_1:
			std::cout << " Option: Next header type is unknown\n";
			break;
		case ICMPV6_OPTION_PARAMETER_PROBLEM_2:
			std::cout << " Option: IPv6 unknown option\n";
			break;
		default:
			std::cout << " Option: Not specified\n";
			break;
		}
		break;
	case ICMPV6_TYPE_ECHO_REQUEST:
		std::cout << " Type: Echo request message\n Code: Not specified\n";
		break;
	case ICMPV6_TYPE_ECHO_REPLY:
		std::cout << " Type: Echo reply message\n Code: Not specified\n";
		break;
	case ICMPV6_TYPE_ROUTER_SOLICITATION:
		std::cout << " Type: Router request message\n Code: Not specified\n";
		break;
	case ICMPV6_TYPE_ADVERTISEMENT:
		std::cout << " Type: Router advertisement message\n Code: Not specified\n";
		break;
	case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:
		std::cout << " Type: Neighbot solicitation message\n Code: Not specified\n";
		break;
	case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
		std::cout << " Type: Neighbor advertisement message\n Code: Not specified\n";
		break;
	case ICMPV6_TYPE_REDIRECT_MESSAGE:
		std::cout << " Type: Redirect message\n Code: Not specified\n";
		break;
	default:
		std::cout << " Type: Not specified\n Code: Not specified\n";
		break;
	}

	// Checksum
	std::cout << " Checksum: ";
	printf("%02X", _packetArrayBytes[ICMPV6_CHECKSUM_BYTE1]);
	printf(":%02X\n", _packetArrayBytes[ICMPV6_CHECKSUM_BYTE2]);

	std::cout << "\n";
}

void Packet::TCP(const unsigned int start_bit, const unsigned int& next_protocol, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int sourcePort(0), destinationPort(0), sequenceNumber(0), acknowledgement(0);
	unsigned int dataPosition(0), flags[9], windowSize(0), urgentPointer(0), options(0), currentByte(0);
	bool dns;

	SetConsoleTextAttribute(STDOUT_HANDLE, 3);
	std::cout << " [TCP]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, 7);

	// Source Port
	sourcePort = BinaryToInteger_256bits(start_bit, start_bit + TCP_SOURCE_PORT_SIZE, _packetArrayBits);
	std::cout << " Source Port: " << sourcePort << " --------------\n";

	//review this
	dns = TPC_UDP_PortCategoryEvaluation(sourcePort);
	dns = false; // If the source port for any reason is dns, is not going to be printed because this is the source port.

	// Destination Port
	destinationPort = BinaryToInteger_256bits(start_bit + 16, start_bit + 32, _packetArrayBits);

	std::cout << " Destination port: " << destinationPort << " --------------\n";

	dns = TPC_UDP_PortCategoryEvaluation(destinationPort);

	std::cout << " --------------------------------------\n";

	// Sequence Number
	sequenceNumber = BinaryToInteger_256bits(start_bit + 32, start_bit + 64, _packetArrayBits);
	std::cout << " Sequence number: " << sequenceNumber << std::endl;

	// Acknowledgement
	acknowledgement = BinaryToInteger_256bits(start_bit + 64, start_bit + 96, _packetArrayBits);
	std::cout << " Acknowledgement: " << acknowledgement << std::endl;

	// Data position
	dataPosition = BinaryToInteger_256bits(start_bit + 96, start_bit + 100, _packetArrayBits);
	std::cout << " Data position: " << dataPosition << std::endl;

	// Reserved (start_bit + 100, start_bit + 103)

	// Active flags (start_bit + 103 to start_bit + 112)
	for (int i = 0; i < 9; ++i) {
		int current_pos = start_bit + 103 + i;

		flags[i] = BinaryToInteger_256bits(current_pos, current_pos + 1, _packetArrayBits);
	}

	std::cout << " Active flags -----------\n";

	if (flags[0])
		std::cout << "NS\n";
	if (flags[1])
		std::cout << "CWR\n";
	if (flags[2])
		std::cout << "ECE\n";
	if (flags[3])
		std::cout << "URG\n";
	if (flags[4])
		std::cout << "ACK\n";
	if (flags[5])
		std::cout << "PSH\n";
	if (flags[6])
		std::cout << "RST\n";
	if (flags[7])
		std::cout << "SYN\n";
	if (flags[8])
		std::cout << "FIN\n";

	std::cout << " ----------------------------\n";

	// Window sizwe
	windowSize = BinaryToInteger_256bits(start_bit + 112, start_bit + 128, _packetArrayBits);
	std::cout << " Window size: " << windowSize << " octetos\n";

	// Checksum
	currentByte = (start_bit + 128) / 8;
	std::cout << " Checksum: ";
	printf("%02X:%02X\n", _packetArrayBytes[currentByte], _packetArrayBytes[currentByte + 1]);

	// Urgent Pointer
	urgentPointer = BinaryToInteger_256bits(start_bit + 144, start_bit + 160, _packetArrayBits);
	std::cout << " Urgent pointer: " << urgentPointer << "\n";

	// Options
	std::cout << "\n";

	if (dns)
		DNS(start_bit + 160);
}

void Packet::UDP(const unsigned int start_bit, const unsigned int& next_protocol, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
}

void Packet::DNS(const unsigned int start_bit)
{
}

bool Packet::TPC_UDP_PortCategoryEvaluation(const unsigned int& port) const
{
	return false;
}

void Packet::DNS_Question_Fields_Evalaution(const unsigned int start_bit)
{
}

void Packet::DNS_Answer_Fields_Evalaution(const unsigned int start_bit)
{
}
