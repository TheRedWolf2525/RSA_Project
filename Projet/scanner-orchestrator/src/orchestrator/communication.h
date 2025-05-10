#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include "../common/protocol.h"

int init_communication(const char* address, int port);

int start_communication();

void accept_connections();

int send_command(int agent_id, const char* command);

int receive_results(int agent_id, char* buffer, size_t buffer_size);

void close_communication();

int get_connected_client_count();

int is_agent_connected(int agent_id);

#endif // COMMUNICATION_H