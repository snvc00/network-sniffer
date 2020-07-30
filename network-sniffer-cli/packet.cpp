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
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [Ethernet]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

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
		SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREYELLOW);
		std::cout << "\n\n WARNING: Undefined type (Not IPv4, IPv6, ARP or RARP)\n";
		std::cin.get();
		SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);
		break;
	}
}

void Packet::IPv4(std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int version, headerLength, typeOfService[IPV4_TYPE_OF_SERVICE_BYTES], totalLength, identifier, flags[IPV4_FLAGS_BYTES];
	unsigned int fragmentOffset, timeToLive, protocol, sourceAddress[IPV4_ADDRESS_BYTES], destinationAddress[IPV4_ADDRESS_BYTES];

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [IPv4]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

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

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [ICMPv4]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

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

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [ARP/RARP]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

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

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [IPv6]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

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

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [ICMPv6]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

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

void Packet::TCP(const unsigned int _startBit, const unsigned int& next_protocol, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int sourcePort(0), destinationPort(0), sequenceNumber(0), acknowledgement(0);
	unsigned int dataPosition(0), flags[9], windowSize(0), urgentPointer(0), options(0), currentByte(0);
	bool dns;

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [TCP]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

	// Source Port
	sourcePort = BinaryToInteger_256bits(_startBit, _startBit + TCP_SOURCE_PORT_SIZE, _packetArrayBits);
	std::cout << " Source Port: " << sourcePort << " --------------\n";
	dns = TPC_UDP_PortCategoryEvaluation(sourcePort);

	// Destination Port
	destinationPort = BinaryToInteger_256bits(_startBit + TCP_DESTINATION_PORT_BEGIN, _startBit + TCP_DESTINATION_PORT_END, _packetArrayBits);
	std::cout << " Destination port: " << destinationPort << " --------------\n";
	dns = TPC_UDP_PortCategoryEvaluation(destinationPort);

	std::cout << " --------------------------------------\n";

	// Sequence Number
	sequenceNumber = BinaryToInteger_256bits(_startBit + TCP_SEQUENCE_NUMBER_BEGIN, _startBit + TCP_SEQUENCE_NUMBER_END, _packetArrayBits);
	std::cout << " Sequence number: " << sequenceNumber << std::endl;

	// Acknowledgement
	acknowledgement = BinaryToInteger_256bits(_startBit + TCP_ACKNOWLEDGEMENT_BEGIN, _startBit + TCP_ACKNOWLEDGEMENT_END, _packetArrayBits);
	std::cout << " Acknowledgement: " << acknowledgement << std::endl;

	// Data position
	dataPosition = BinaryToInteger_256bits(_startBit + TCP_DATA_POSITION_BEGIN, _startBit + TCP_DATA_POSITION_END, _packetArrayBits);
	std::cout << " Data position: " << dataPosition << std::endl;

	// Reserved (_startBit + 100, _startBit + 103)

	// Active flags (_startBit + 103 to _startBit + 112)
	for (int i = TCP_FLAG_NS; i < TCP_FLAG_SIZE; ++i) {
		int current_pos = _startBit + TCP_ACTIVE_FLAGS_BEGIN + i;
		flags[i] = BinaryToInteger_256bits(current_pos, current_pos + 1, _packetArrayBits);
	}

	std::cout << " Active flags -----------\n";

	if (flags[TCP_FLAG_NS])
		std::cout << " NS\n";
	if (flags[TCP_FLAG_CWR])
		std::cout << " CWR\n";
	if (flags[TCP_FLAG_ECE])
		std::cout << " ECE\n";
	if (flags[TCP_FLAG_URG])
		std::cout << " URG\n";
	if (flags[TCP_FLAG_ACK])
		std::cout << " ACK\n";
	if (flags[TCP_FLAG_PSH])
		std::cout << " PSH\n";
	if (flags[TCP_FLAG_RST])
		std::cout << " RST\n";
	if (flags[TCP_FLAG_SYN])
		std::cout << " SYN\n";
	if (flags[TCP_FLAG_FIN])
		std::cout << " FIN\n";

	std::cout << " ----------------------------\n";

	// Window size
	windowSize = BinaryToInteger_256bits(_startBit + TCP_WINDOW_SIZE_BEGIN, _startBit + TCP_WINDOW_SIZE_END, _packetArrayBits);
	std::cout << " Window size: " << windowSize << " octets\n";

	// Checksum
	currentByte = (_startBit + TCP_CHECKSUM_BEGIN) / 8; // Divided by 8 to convert from bit number to byte number
	std::cout << " Checksum: ";
	printf("%02X:%02X\n", _packetArrayBytes[currentByte], _packetArrayBytes[currentByte + 1]);

	// Urgent Pointer
	urgentPointer = BinaryToInteger_256bits(_startBit + TCP_URGENT_POINTER_BEGIN, _startBit + TCP_URGENT_POINTER_END, _packetArrayBits);
	std::cout << " Urgent pointer: " << urgentPointer << "\n";

	// Options
	std::cout << "\n";

	if (dns)
		DNS(_startBit + TCP_START_DNS_OFFSET, _packetArrayBytes, _packetArrayBits);
}

void Packet::UDP(const unsigned int _startBit, const unsigned int& next_protocol, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int sourcePort(0), destinationPort(0), currentByte(0);
	bool dns;

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [UDP]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

	// Source Port
	sourcePort = BinaryToInteger_256bits(_startBit, _startBit + UDP_SOURCE_PORT_SIZE, _packetArrayBits);

	std::cout << " (Source port: " << sourcePort << ")-----------------\n";

	dns = TPC_UDP_PortCategoryEvaluation(sourcePort);
	dns = false; // If the source port for any reason is dns, is not going to be printed because this is the source port.

	// Destination Port
	destinationPort = BinaryToInteger_256bits(_startBit + UDP_DESTINATION_PORT_BEGIN, _startBit + UDP_DESTINATION_PORT_END, _packetArrayBits);

	std::cout << " (Destination port: " << destinationPort << ")-------------------\n";

	dns = TPC_UDP_PortCategoryEvaluation(destinationPort);

	// Length
	currentByte = (_startBit + UDP_LENGTH_BEGIN) / 8; // Divided by 8 to convert from bit number to byte number
	std::cout << " Length: ";
	printf("%02X:%02X\n", _packetArrayBytes[currentByte], _packetArrayBytes[currentByte + 1]);

	// Checksum
	currentByte = (_startBit + UDP_CHECKSUM_BEGIN) / 8; // Divided by 8 to convert from bit number to byte number
	std::cout << " Checksum: ";
	printf("%02X:%02X\n", _packetArrayBytes[currentByte], _packetArrayBytes[currentByte + 1]);

	std::cout << "\n";

	if (dns)
		DNS(_startBit + UDP_START_DNS_OFFSET, _packetArrayBytes, _packetArrayBits);
}

void Packet::DNS(const unsigned int _startBit, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int currentByte(0), QR(0), opCode(0), AA(0), TC(0), RD(0), RA(0), AD(0), CD(0), rCode(0);
	unsigned int QDcount(0), ANcount(0), NScount(0), ARcount(0), dClass(0), f_type(0), currentBit(0);
	std::string domainName;

	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREAQUA);
	std::cout << " [DNS]\n";
	SetConsoleTextAttribute(STDOUT_HANDLE, BACKBLACK_FOREWHITE);

	// ID
	currentByte = (_startBit) / 8; // Divided by 8 to convert from bit number to byte number
	std::cout << " ID: ";
	printf("%02X:%02X\n", _packetArrayBytes[currentByte], _packetArrayBytes[currentByte + 1]);

	// Flags
	std::cout << " Flags: ---------------------------\n";

	QR = BinaryToInteger_256bits(_startBit + DNS_QR_BEGIN, _startBit + DNS_QR_END, _packetArrayBits);
	if (QR)
		std::cout << " Description: Answer\n";
	else
		std::cout << " Description: Question\n";

	opCode = BinaryToInteger_256bits(_startBit + DNS_OP_CODE_BEGIN, _startBit + DNS_OP_CODE_END, _packetArrayBits);
	if (opCode == DNS_OP_CODE_STANDARD)
		std::cout << " QUERY - Standard query\n";
	else if (opCode == DNS_OP_CODE_INVERSE)
		std::cout << " IQUERY- Inverse query\n";
	else if (opCode == DNS_OP_CODE_STATUS)
		std::cout << " STATUS - Service status query\n";

	AA = BinaryToInteger_256bits(_startBit + DNS_AA_BEGIN, _startBit + DNS_AA_END, _packetArrayBits);
	if (AA)
		std::cout << " Authoritative\n";
	else
		std::cout << " Not Authoritative\n";

	TC = BinaryToInteger_256bits(_startBit + DNS_TC_BEGIN, _startBit + DNS_TC_END, _packetArrayBits);
	if (TC)
		std::cout << " Truncated message\n";
	else
		std::cout << " Not truncated message\n";

	RD = BinaryToInteger_256bits(_startBit + DNS_RD_BEGIN, _startBit + DNS_RD_END, _packetArrayBits);
	if (RD)
		std::cout << " Recursive\n";
	else
		std::cout << " Not recursive\n";

	RA = BinaryToInteger_256bits(_startBit + DNS_RA_BEGIN, _startBit + DNS_RA_END, _packetArrayBits);
	if (RA)
		std::cout << " Recursive query available\n";
	else
		std::cout << " Recursive query not available\n";

	std::cout << " -------------------------------------\n";

	// Return Code
	rCode = BinaryToInteger_256bits(_startBit + DNS_RETURN_CODE_BEGIN, _startBit + DNS_RETURN_CODE_END, _packetArrayBits);
	std::cout << " Return code: ";

	switch (rCode)
	{
	case DNS_RETURN_CODE_NO_ERROR:
		std::cout << " No error\n";
		break;
	case DNS_RETURN_CODE_FORMAT_ERROR:
		std::cout << " Format error\n";
		break;
	case DNS_RETURN_CODE_SERVER_ERROR:
		std::cout << " Server error\n";
		break;
	case DNS_RETURN_CODE_NAME_ERROR:
		std::cout << " Name error\n";
		break;
	case DNS_RETURN_CODE_NOT_IMPLEMENTED:
		std::cout << " Not implemented\n";
		break;
	case DNS_RETURN_CODE_REJECTED:
		std::cout << " Rejected\n";
		break;
	default:
		std::cout << " Unknown\n";
		break;
	}

	// Counters
	QDcount = BinaryToInteger_256bits(_startBit + DNS_QD_BEGIN, _startBit + DNS_QD_END, _packetArrayBits);
	std::cout << " Number of RRs on Question: " << QDcount << "\n";

	ANcount = BinaryToInteger_256bits(_startBit + DNS_AN_BEGIN, _startBit + DNS_AN_END, _packetArrayBits);
	std::cout << " Number of RRs on Answer: " << ANcount << "\n";

	NScount = BinaryToInteger_256bits(_startBit + DNS_NS_BEGIN, _startBit + DNS_NS_END, _packetArrayBits);
	std::cout << " Number of RRs on Authority: " << NScount << "\n";

	ARcount = BinaryToInteger_256bits(_startBit + DNS_AR_BEGIN, _startBit + DNS_AR_END, _packetArrayBits);
	std::cout << " Number of RRs on Additional Records: " << ARcount << "\n";

	// Questions
	for (unsigned int i(0); i < QDcount; ++i)
		DNS_Question_Fields_Evalaution(_startBit + DNS_QUESTION_ANSWER, _packetArrayBytes, _packetArrayBits);

	// Answers
	for (unsigned int i(0); i < ANcount; ++i)
		DNS_Answer_Fields_Evalaution(_startBit + DNS_QUESTION_ANSWER, _packetArrayBytes, _packetArrayBits);

	std::cout << "\n";
}

bool Packet::TPC_UDP_PortCategoryEvaluation(const unsigned int& _port) const
{
    bool dns = false;

	if (_port < WELL_KNOWN_PORT_SUPERIOR_LIMIT)
		std::cout << " Port category: Well known port\n";
	else if (_port > REGISTERED_PORT_INFERIOR_LIMIT && _port < REGISTERED_PORT_SUPERIOR_LIMIT)
		std::cout << " Port category: Registered port\n";
	else
		std::cout << " Port category: Dynamic or private port\n";

	switch (_port)
	{
	case SFTP_PTCP: 
		std::cout << " Service: FTP\n" << " Protocol: TCP\n";
		break;
	case SFTP_PUDP:
		std::cout << " Service: FTP\n" << " Protocol: UDP\n";
		break;
	case SSSH_PTCP:
		std::cout << " Service: SSH\n" << " Protocol: TCP\n";
		break;
	case STELNET_PTCP:
		std::cout << " Service: TELNET\n" << " Protocol: TCP\n";
		break;
	case SSSMTP_PTCP:
		std::cout << " Service: SSMTP\n" << " Protocol: TCP\n";
		break;
	case SDNS_PTCP_UDP:
		std::cout << " Service: DNS\n" << " Protocol: TCP / UDP\n";
		dns = true;
		break;
	case SDHCP_UDP:
		std::cout << " Service: DHCP\n" << " Protocol: UDP\n";
		break;
	case SDHCP_UDP_1:
		std::cout << " Service: DHCP\n" << " Protocol: UDP\n";
		break;
	case STFTP_PUDP:
		std::cout << " Service: TFTP\n" << " Protocol: UDP\n";
		break;
	case SHTTP_PTCP:
		std::cout << " Service: HTTP\n" << " Protocol: TCP\n";
		break;
	case SPOP3_PTCP:
		std::cout << " Service: POP3\n" << " Protocol: TCP\n";
		break;
	case SIMAP_PTCP:
		std::cout << " Service: IMAP\n" << " Protocol: TCP\n";
		break;
	case SHTTPS_PTCP:
		std::cout << " Service: HTTPS\n" << " Protocol: TCP\n";
		break;
	case SIMAPSSL_PTCP:
		std::cout << " Service: IMAP SSL\n" << " Protocol: TCP\n";
		break;
	case SPOPSSL_PTCP:
		std::cout << " Service: POP SSL\n" << " Protocol: TCP\n";
		break;
	default:
		std::cout << " Service: Unknown\n" << " Protocol: Unknown\n";
		break;
	}

	return dns;
}

void Packet::DNS_Question_Fields_Evalaution(const unsigned int _startBit, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int dClass(0), type(0), currentBit = _startBit;
	unsigned int currentByte = SIZE_ETHERNET + (currentBit / 8);
	std::string domainName;

	unsigned int letters(0);
	unsigned char aux;
	bool domainIncomplete = true;

	while (domainIncomplete) {
		letters = BinaryToInteger_256bits(currentBit, currentBit + DNS_LETTER_FIELD_SIZE, _packetArrayBits);

		if (letters != 0) {
			for (unsigned int j(0); j < letters; ++j) {
				++currentByte;
				aux = ByteToChar(currentByte, _packetArrayBytes);
				domainName.push_back(aux);
				currentBit += DNS_LETTER_FIELD_SIZE;
			}
			domainName.push_back("."[0]);
			++currentByte;
			currentBit += DNS_LETTER_FIELD_SIZE;
		}
		else {
			domainName.pop_back();
			currentBit += DNS_LETTER_FIELD_SIZE;
			domainIncomplete = false;
		}
	}

	std::cout << " Domain name: " << domainName << "\n";

	type = BinaryToInteger_256bits(currentBit, currentBit + DNS_TYPE_FIELD_SIZE, _packetArrayBits);
	currentBit += DNS_TYPE_FIELD_SIZE;

	switch (type)
	{
	case DNS_TYPE_A:
		std::cout << " Type: A\n";
		break;
	case DNS_TYPE_CNAME:
		std::cout << " Type: CNAME\n";
		break;
	case DNS_TYPE_HINFO:
		std::cout << " Type: HINFO\n";
		break;
	case DNS_TYPE_MX:
		std::cout << " Type: MAIL EXCHANGE\n";
		break;
	case DNS_TYPE_NS:
		std::cout << " Type: NS\n";
		break;
	default:
		std::cout << " Type: Unknown\n";
		break;
	}

	dClass = BinaryToInteger_256bits(currentBit, currentBit + DNS_CLASS_FIELD_SIZE, _packetArrayBits);

	if (dClass == DNS_CLASS_INTERNET_PROTOCOLS)
		std::cout << " Class: IN - Internet protocols\n";
	else if (dClass == DNS_CLASS_CHAOTIC_SYSTEM)
		std::cout << " Class: CH - Chaotic system\n";
	else
		std::cout << " Class: Unknown\n";
}

void Packet::DNS_Answer_Fields_Evalaution(const unsigned int _startBit, std::vector<unsigned char>& _packetArrayBytes, std::vector<unsigned char>& _packetArrayBits)
{
	unsigned int dClass(0), type(0), ttl(0), currentBit(_startBit);
	unsigned int currentByte = SIZE_ETHERNET + (currentBit / 8);
	std::string domainName;

	unsigned int letters(0);
	unsigned char aux;
	bool domainIncomplete = true;

	while (domainIncomplete) {
		letters = BinaryToInteger_256bits(currentBit, currentBit + DNS_LETTER_FIELD_SIZE, _packetArrayBits);

		if (letters != 0) {
			for (unsigned int j(0); j < letters; ++j) {
				++currentByte;
				aux = ByteToChar(currentByte, _packetArrayBytes);
				domainName.push_back(aux);
				currentBit += DNS_LETTER_FIELD_SIZE;
			}
			domainName.push_back("."[0]);
			++currentByte;
			currentBit += DNS_LETTER_FIELD_SIZE;
		}
		else {
			domainName.pop_back();
			currentBit += DNS_LETTER_FIELD_SIZE;
			domainIncomplete = false;
		}
	}

	std::cout << " Domain name: " << domainName << "\n";

	type = BinaryToInteger_256bits(currentBit, currentBit + DNS_TYPE_FIELD_SIZE, _packetArrayBits);
	currentBit += DNS_TYPE_FIELD_SIZE;

	switch (type)
	{
	case DNS_TYPE_A:
		std::cout << " Type: A\n";
		break;
	case DNS_TYPE_CNAME:
		std::cout << " Type: CNAME\n";
		break;
	case DNS_TYPE_HINFO:
		std::cout << " Type: HINFO\n";
		break;
	case DNS_TYPE_MX:
		std::cout << " Type: MAIL EXCHANGE\n";
		break;
	case DNS_TYPE_NS:
		std::cout << " Type: NS\n";
		break;
	default:
		std::cout << " Type: Unknown\n";
		break;
	}

	dClass = BinaryToInteger_256bits(currentBit, currentBit + DNS_CLASS_FIELD_SIZE, _packetArrayBits);

	if (dClass == DNS_CLASS_INTERNET_PROTOCOLS)
		std::cout << " Class: IN - Internet protocols\n";
	else if (dClass == DNS_CLASS_CHAOTIC_SYSTEM)
		std::cout << " Class: CH - Chaotic system\n";
	else
		std::cout << " Class: Unknown\n";

	ttl = 0;
	std::cout << " Time to live: " << ttl << "\n";

	printf(" Data length: %02X:%02X", _packetArrayBytes[DNS_TIME_TO_LIVE_BYTE1], _packetArrayBytes[DNS_TIME_TO_LIVE_BYTE2]);

	std::cout << " Register type: \n";
}
