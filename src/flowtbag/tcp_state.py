#!/usr/bin/python

'''
   Copyright 2011 Daniel Arndt

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Contributors:

   @author: Daniel Arndt <danielarndt@gmail.com>
'''

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

def tcp_set(flags, find):
    '''
    Checks if a flag is set or not.
    
    Args:
        find - The flag to find
        flags - The string encoded set of flags
    Returns:
        True - if the /find/ flag is set
        False - otherwise
    '''
    return ((find & flags) == find)

#==============================================================================#
# TCP connection states. These define the finite state machine used for        #
# verifying TCP flow validity.                                                 #
#==============================================================================#
class STATE_TCP(object):
    ''' 
    Superclass for a TCP connection state machine.  
    
    Defines the behavior of a state within a generalized finite state machine.
    Currently, the rules perfectly resemble those used by NetMate
    '''
    #TODO: Update the state machine to include more robust checks. Current 
    # implementation imitates NetMate state machine. 
    def update(self, flags, dir, _pdir):
        '''
        Updates the TCP state machine.
        
        First the RST and FIN flags are checked. If either of these are set, the
        connection state is set to either TCP_CLOSED or TCP_FIN respectively.
        Next, the function attempts to find a transition,
        If no transition is found, then the function returns itself. 
        
        '''
        if tcp_set(flags, TCP_RST):
            return STATE_TCP_CLOSED()
        if tcp_set(flags, TCP_FIN) and dir == _pdir:
            return STATE_TCP_FIN()
        return self.tr(flags, dir, _pdir)

    def __str__(self):
        return self.__class__.__name__

class STATE_TCP_START(STATE_TCP):
    def tr(self, flags, dir, pdir):
        if tcp_set(flags, TCP_SYN) and dir == pdir:
           return STATE_TCP_SYN()
        return self
        
class STATE_TCP_SYN(STATE_TCP):
    def tr(self, flags, dir, pdir):
        if tcp_set(flags, TCP_SYN) and tcp_set(flags, TCP_ACK) and dir != pdir:
            return  STATE_TCP_SYNACK()
        return self

class STATE_TCP_SYNACK(STATE_TCP):
    def tr(self, flags, dir, pdir):
        if tcp_set(flags, TCP_ACK) and dir == pdir:
            return STATE_TCP_ESTABLISHED()
        return self

class STATE_TCP_ESTABLISHED(STATE_TCP):
    def tr(self, flags, dir, pdir):
        return self
    
class STATE_TCP_FIN(STATE_TCP):
    def tr(self, flags, dir, pdir):
        if tcp_set(flags, TCP_ACK) and dir != pdir:
            return STATE_TCP_CLOSED()
        return self

class STATE_TCP_CLOSED(STATE_TCP):
    def tr(self, flags, dir, pdir):
        return self
#-------------------------------------------------------- End: TCP state machine
