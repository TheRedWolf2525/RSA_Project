#ifndef AGENT_COMMUNICATION_H
#define AGENT_COMMUNICATION_H

#include "../common/messages.h"

int initialize_communication(const char* orchestrator_address, int port);

int send_message(const Message* msg);

int receive_message(Message* msg);

void close_communication();

#endif // AGENT_COMMUNICATION_H