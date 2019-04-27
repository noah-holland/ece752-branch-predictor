import re

from gzip import GzipFile
from types import SimpleNamespace

__HEX_RE  = r'((?:0x)?[0-9a-f\-]+)'
__TYPE_RE = r'((?:[A-Z]\+?)+)'

# When using {n} to captures repeating patterns it only captures the last occurance :(
_NODE_RE = re.compile(f'''^NODE \s+
                          (\d+) \s+       # id
                          {__HEX_RE} \s+  #  virtual_address
                          {__HEX_RE} \s+  # physical_address
                          {__HEX_RE} \s+  # opcode
                          (\d+) \s+       # size
                         # everything here on out is optional
                        (?:[\w:]+ \s+ {__TYPE_RE} \s+ )?   # class
                        (?:[\w:]+ \s+ {__TYPE_RE} \s+ )?   # behavior
                        (?:[\w:]+ \s+ (\d+) \s+       )?   # taken_cnt
                        (?:[\w:]+ \s+ (\d+) \s+       )?   # not_taken_cnt
                        (?:[\w:]+ \s+ (\d+) \s+       )?   # tgt_cnt
                        (?:\# [\w:\s]+ \" ([\s\w]+)   )?   # mnemonic
                        ''', re.VERBOSE)

_EDGE_RE = re.compile(f'''^EDGE \s+
                          (\d+) \s+        # id
                          (\d+) \s+        # src_id
                          (\d+) \s+        # dest_id
                          ([NT]) \s+       # taken
                          {__HEX_RE} \s+   # br_virt_target
                          {__HEX_RE} \s+   # br_phy_target
                          (\d+)            # inst_cnt
                          [\w\s_:]+ (\d+)  # traverse_cnt
                          ''', re.VERBOSE)

class Edge(SimpleNamespace):
    def __init__(self, id=None, src_id=None, dest_id=None, taken=None,
                 br_virt_target=None, br_phy_target=None, inst_cnt = None, traverse_cnt=None):

        super().__init__(id=int(id), src_id=int(src_id), dest_id=int(dest_id), taken=(taken == 'T'),
                     br_virt_target=br_virt_target, br_phy_target=br_phy_target, inst_cnt = int(inst_cnt), traverse_cnt=int(traverse_cnt))

class Node(SimpleNamespace):
    def __init__(self, id=None, virtual_address=None, physical_address=None, opcode=None, size=None,
                 clss=None, behavior=None, taken_cnt = 0, not_taken_cnt=0, tgt_cnt=0, mnemonic=None):

        super().__init__(id=int(id), virtual_address=virtual_address, physical_address=physical_address, opcode=opcode, size=int(size),
                     clss=clss, behavior=behavior, taken_cnt=int(taken_cnt or 0), not_taken_cnt=int(not_taken_cnt or 0), tgt_cnt=int(tgt_cnt or 0), mnemonic=mnemonic)

class BT9(GzipFile):
    header = ''
    nodes  = []
    edges  = []

    _edge_list_start = None
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._readHeader()

    def _readHeader(self):
        if not self.header:
            self.seek(0)

            while 'BT9_EDGE_SEQUENCE' not in self.header:
                line = self.readline().decode()
                self.header += line
                node = _NODE_RE.match(line)
                edge = _EDGE_RE.match(line)
                if node:
                    self.nodes.append(Node(*node.groups()))
                elif edge:
                    self.edges.append(Edge(*edge.groups()))

            self._edge_list_start = self.tell()

    def __next__(self):
        edge = self.readline()
        if b'EOF' in edge or not edge:
            raise StopIteration
        return self.edges[int(edge)]

if __name__ == '__main__':
    trace = BT9("../traces/SHORT_MOBILE-27.bt9.trace.gz")
