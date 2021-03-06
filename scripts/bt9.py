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

    _edge_list_start = None
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.header = ''
        self.nodes  = []
        self.edges  = []
        self._readHeader()

    def _readHeader(self):
        if not self.header:
            self.seek(0)

            # I'm not sure why, but putting it directly into self.header bottlenecks
            # Causing it to take at least 30 min for SHORT_MOBILE_20, when it only takes
            # 3 seconds this way
            h = ''

            while True:
                line = self.readline().decode()
                h += line
                if 'BT9_EDGE_SEQUENCE' in line:
                    break
                node = _NODE_RE.match(line)
                edge = _EDGE_RE.match(line)
                if node:
                    self.nodes.append(Node(*node.groups()))
                elif edge:
                    self.edges.append(Edge(*edge.groups()))

            self.header = h
            self._edge_list_start = self.tell()

    def __next__(self):
        edge = self.readline()
        if b'EOF' in edge or not edge:
            raise StopIteration
        return self.edges[int(edge)]

    @property
    def graph(self):
        try:
            from graph_tool import Graph
        except ImportError:
            return None

        g = Graph()
        g.add_vertex(len(self.nodes))
        g.add_edge_list([(e.src_id, e.dest_id) for e in self.edges])

        return g


if __name__ == '__main__':
    trace = BT9("../traces/SHORT_MOBILE-20.bt9.trace.gz")
