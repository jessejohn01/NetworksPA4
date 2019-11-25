import queue
import threading
from collections import defaultdict


# # wrapper class for a queue of packets
class Interface:

    # # @param maxsize - the maximum size of the queue storing packets
    def __init__(self, maxsize=0):
        self.in_queue = queue.Queue(maxsize)
        self.out_queue = queue.Queue(maxsize)
    
    # #get packet from the queue interface
    # @param in_or_out - use 'in' or 'out' interface
    def get(self, in_or_out):
        try:
            if in_or_out == 'in':
                pkt_S = self.in_queue.get(False)
                # if pkt_S is not None:
                #     print('getting packet from the IN queue')
                return pkt_S
            else:
                pkt_S = self.out_queue.get(False)
                # if pkt_S is not None:
                #     print('getting packet from the OUT queue')
                return pkt_S
        except queue.Empty:
            return None
        
    # #put the packet into the interface queue
    # @param pkt - Packet to be inserted into the queue
    # @param in_or_out - use 'in' or 'out' interface
    # @param block - if True, block until room in queue, if False may throw queue.Full exception
    def put(self, pkt, in_or_out, block=False):
        if in_or_out == 'out':
            # print('putting packet in the OUT queue')
            self.out_queue.put(pkt, block)
        else:
            # print('putting packet in the IN queue')
            self.in_queue.put(pkt, block)
            
        
# # Implements a network layer packet.
class NetworkPacket:
    # # packet encoding lengths 
    dst_S_length = 5
    prot_S_length = 1
    
    # #@param dst: address of the destination host
    # @param data_S: packet payload
    # @param prot_S: upper layer protocol for the packet (data, or control)
    def __init__(self, dst, prot_S, data_S):
        self.dst = dst
        self.data_S = data_S
        self.prot_S = prot_S
        
    # # called when printing the object
    def __str__(self):
        return self.to_byte_S()
        
    # # convert packet to a byte string for transmission over links
    def to_byte_S(self):
        byte_S = str(self.dst).zfill(self.dst_S_length)
        if self.prot_S == 'data':
            byte_S += '1'
        elif self.prot_S == 'control':
            byte_S += '2'
        else:
            raise('%s: unknown prot_S option: %s' % (self, self.prot_S))
        byte_S += self.data_S
        return byte_S
    
    # # extract a packet object from a byte string
    # @param byte_S: byte string representation of the packet
    @classmethod
    def from_byte_S(self, byte_S):
        dst = byte_S[0 : NetworkPacket.dst_S_length].strip('0')
        prot_S = byte_S[NetworkPacket.dst_S_length : NetworkPacket.dst_S_length + NetworkPacket.prot_S_length]
        if prot_S == '1':
            prot_S = 'data'
        elif prot_S == '2':
            prot_S = 'control'
        else:
            raise('%s: unknown prot_S field: %s' % (self, prot_S))
        data_S = byte_S[NetworkPacket.dst_S_length + NetworkPacket.prot_S_length : ]        
        return self(dst, prot_S, data_S)
    

# # Implements a network host for receiving and transmitting data
class Host:
    
    # #@param addr: address of this node represented as an integer
    def __init__(self, addr):
        self.addr = addr
        self.intf_L = [Interface()]
        self.stop = False  # for thread termination
    
    # # called when printing the object
    def __str__(self):
        return self.addr
       
    # # create a packet and enqueue for transmission
    # @param dst: destination address for the packet
    # @param data_S: data being transmitted to the network layer
    def udt_send(self, dst, data_S):
        p = NetworkPacket(dst, 'data', data_S)
        print('%s: sending packet "%s"' % (self, p))
        self.intf_L[0].put(p.to_byte_S(), 'out')  # send packets always enqueued successfully
        
    # # receive packet from the network layer
    def udt_receive(self):
        pkt_S = self.intf_L[0].get('in')
        if pkt_S is not None:
            print('%s: received packet "%s"' % (self, pkt_S))
       
    # # thread target for the host to keep receiving data
    def run(self):
        print (threading.currentThread().getName() + ': Starting')
        while True:
            # receive data arriving to the in interface
            self.udt_receive()
            # terminate
            if(self.stop):
                print (threading.currentThread().getName() + ': Ending')
                return


# # Implements a multi-interface router
class Router:
    
    # #@param name: friendly router name for debugging
    # @param cost_D: cost table to neighbors {neighbor: {interface: cost}}
    # @param max_queue_size: max queue length (passed to Interface)
    def __init__(self, name, cost_D, max_queue_size):
        self.stop = False  # for thread termination
        self.name = name
        # create a list of interfaces
        self.intf_L = [Interface(max_queue_size) for _ in range(len(cost_D))]
        # save neighbors and interfaces on which we connect to them
        self.cost_D = cost_D  # {neighbor: {interface: cost}}
        self.total_rt = defaultdict(dict)

        self.rt_tbl_D = cost_D.copy()
        
        print('%s: Initialized routing table' % self)
        self.print_routes()
        
    # # Print routing table
    def print_routes(self):
        
        print("Router " + self.name + " is sending a packet.")
        
        rowBorder = "|==="  # Create our known routers rows.
        for i in range(len(self.rt_tbl_D.keys())):
            rowBorder += '|==='
        rowBorder += '|'
        print(rowBorder)       
        
        tableName = '|' + self.name + ' |'  # Which router does this table belong to?
        for dest in self.rt_tbl_D.keys():
            tableName += dest + ' |'
        print(tableName)
        print(rowBorder)
        
        column = '|' + self.name + ' | '  # What destinations are available?
        for value in self.rt_tbl_D.values():
            for y in value.values():
                column += str(y) + ' | '
        print(column)
        print(rowBorder + '\n')        

    # # called when printing the object
    def __str__(self):
        return self.name

    # # look through the content of incoming interfaces and 
    # process data and control packets
    def process_queues(self):
        for i in range(len(self.intf_L)):
            pkt_S = None
            # get packet from interface i
            pkt_S = self.intf_L[i].get('in')
            # if packet exists make a forwarding decision
            if pkt_S is not None:
                p = NetworkPacket.from_byte_S(pkt_S)  # parse a packet out
                if p.prot_S == 'data':
                    self.forward_packet(p, i)
                elif p.prot_S == 'control':
                    self.update_routes(p, i)
                else:
                    raise Exception('%s: Unknown packet type in packet %s' % (self, p))

    # # forward the packet according to the routing table
    #  @param p Packet to forward
    #  @param i Incoming interface number for packet p
    def forward_packet(self, p, i):
        try:
 
            route = self.rt_tbl_D.get(str(p.dst))  # Use table to find destination.

            for interface, cost, in route.items():  # Which interface are we forwarding to? 
                print("interface,", interface, "cost,", cost, "Route:", route)
                to_forward = int(interface)
                break
            self.intf_L[to_forward].put(p.to_byte_S(), 'out', True)
            print('%s: forwarding packet "%s" from interface %d to %d' % \
                  (self, p, i, 1))
        except queue.Full:
            print('%s: packet "%s" lost on interface %d' % (self, p, i))
            pass

    # # send out route update
    # @param i Interface number on which to send out a routing update
    def send_routes(self, i):
        
        # create a routing table update packet
        routing_table = self.name + "#"
        for j, k in self.rt_tbl_D.items():
            for neighbor, cost in k.items():
                routing_table += str(j) + "|" + str(neighbor) + "|" + str(cost) + "%"
                print(j, neighbor, cost)
        p = NetworkPacket(0, 'control', routing_table)
        try:
            print('%s: sending routing update "%s" from interface %d' % (self, p, i))
            self.intf_L[i].put(p.to_byte_S(), 'out', True)
        except queue.Full:
            print('%s: packet "%s" lost on interface %d' % (self, p, i))
            pass

    # # forward the packet according to the routing table
    #  @param p Packet containing routing information
    def update_routes(self, p, i):
        updated = False  # Haven't updated anything.
        # Decode
        table = p.data_S.split("#")
        name_table = table[0]
        routes = table[1].split("%")

        for route in routes:  # Splitting up the information into variables.
            if route != '':
                node = route.split("|")
            
            self.total_rt[name_table][node[0]] = [int(node[2])]  # Adds to global table

            if node[0] == self.name:  # Check if self. If so set and skip
                
                inf = list(self.cost_D[name_table].keys())  # Get interface of neighbor
               
                self.rt_tbl_D[node[0]] = {int(inf[0]): 0}  # Distance from new node to neighbor to node.

                self.total_rt[self.name][node[0]] = [0]  # Adds to global table

            if node[0] not in self.cost_D and  node[0] not in self.rt_tbl_D:  # Checks if the node is not already in the table or not a neighbor

                n = list(self.cost_D[name_table].values())
                inf = list(self.cost_D[name_table].keys())
                self.rt_tbl_D[node[0]] = {int(inf[0]):int(node[2]) + n[0]}
                self.total_rt[self.name][node[0]] = [int(node[2]) + n[0]]

                updated = True

            elif node[0] not in self.cost_D and  node[0] in self.rt_tbl_D:
                n = list(self.cost_D[name_table].values())
                inf = list(self.cost_D[name_table].keys())
                curr = list(self.rt_tbl_D[node[0]].values())
                if curr[0] > int(n[0]) + int(node[2]):
                    self.rt_tbl_D[node[0]] = {int(inf[0]):int(node[2]) + n[0]}
                    self.total_rt[self.name][node[0]] = [int(node[2]) + n[0]]

                    updated = True  # Update list.

        if updated:  # Notifies neighbor's if we have updated
            for neighbor_name, neighbor_info in self.cost_D.items():
                for interface, cost in neighbor_info.items():
                    if 'H' not in neighbor_name:  # Checks if the neighbor is a host
                        self.send_routes(interface)
        print('%s: Received routing update %s from interface %d' % (self, p, i))
 
    # # thread target for the host to keep forwarding data
    def run(self):
        print (threading.currentThread().getName() + ': Starting')
        while True:
            self.process_queues()
            if self.stop:
                print (threading.currentThread().getName() + ': Ending')
                return 
