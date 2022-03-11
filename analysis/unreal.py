import hashlib
from analysis.node import Node, NodeType
from common.logger import Logger
from gui.filewriter import FileReader


class UnrealNode(Node):
    def __init__(self, type, toc_entry=None):
        super(UnrealNode, self).__init__(type)
        self.toc_entry = toc_entry
        self.possible_matched_nodes = []
        self._is_md5_match = False
        self._matched_node = None

    def set_matched_node(self, node, is_md5_match=False):
        self._is_md5_match = is_md5_match
        self._matched_node = node
        self.copy_node_properties_to_node(node)

    def copy_node_properties_to_node(self, node):
        self.set_inode(node.get_inode())
        self.set_direct(node.get_direct())
        self.set_direct_offset(node.get_direct_offset())
        self.set_directory_offset(node.get_directory_offset())
        self.set_active(node.get_active())
        self.set_file_offset(node.get_file_offset())
        # for k in node.__dict__:
        #     setattr(self, k, getattr(node, k))


class UnrealTOCEntry():
    def __init__(self):
        self.filesize = None
        self.md5 = None
        self.name = None
        self.filepath = None


class UnrealTOC():
    def __init__(self, toc_node, toc_str):
        self.toc_node = toc_node
        self.toc_str = toc_str
        self.toc_entries = self.parse_toc_str(self.toc_str)
        self.unreal_nodes = self.create_unodes()


    def parse_toc_str(self, toc_str):
        entries = []
        toc_lines = toc_str.split("\n")
        for line in toc_lines:
            if line == '':
                continue
            toc_entry = UnrealTOCEntry()

            # Invalid line if there isn't an int here... move to next, it may be fragged
            try:
                toc_entry.filesize = int(line.split()[0])
            except Exception:
                continue

            entry_items = line.split()
            for item in entry_items:
                if "..\\" in item:
                    if(len(item.rsplit("\\", 1)[0].split("..\\")) <= 1 ):
                        toc_entry.filepath = ''
                    else:
                        toc_entry.filepath = item.rsplit("\\", 1)[0].split("..\\")[1]
                    toc_entry.name = item.split("\\")[-1]
                elif len(item) == 32:
                    toc_entry.md5 = item
            entries.append(toc_entry)
        return entries
        
    def create_unodes(self):
        unodes = [] 
        node_dir_path_map = {}
        for entry in self.toc_entries:
            entry: UnrealTOCEntry
            if entry.filepath == None:
                continue
            directories = entry.filepath.split("\\")
            current_path = ""
            for directory in directories:
                current_path += "\\" + directory
                if current_path not in node_dir_path_map:
                    node = UnrealNode(NodeType.DIRECTORY)
                    node.set_name(directory)
                    unodes.append(node)
                    node_dir_path_map[current_path] = node
                    parent_path = current_path.rsplit("\\", 1)[0]
                    if parent_path != '':
                        parent = node_dir_path_map.get(parent_path)
                        parent.add_child(node)
                        node.add_parent(parent)
                    
            node = UnrealNode(NodeType.FILE, entry)
            node.set_name(entry.name.rsplit(".",1)[0])
            node.set_size(entry.filesize)
            
            # This catches some TOCs that were fragged and stop before the filename ends
            if(len(entry.name.split(".")) > 1):
                node.set_file_ext("." + entry.name.split(".")[1])
            
            unodes.append(node)

            if entry.filepath != '':
                parent = node_dir_path_map.get(current_path)
                parent.add_child(node)
                node.add_parent(parent)
            
        return unodes


class UnrealAnalyzer():
    def __init__(self, nodes, stream):
        self._all_nodes = nodes
        self._stream = stream
        self._filereader = FileReader(stream)
        self._toc_nodes = self.filter_toc_nodes(self._all_nodes)
        self._md5_node_map = None
        self._size_node_map = None
        self.unreal_tocs = self.parse_toc_nodes(self._toc_nodes)
        self._taken_nodes = {}

    def parse_toc_node_to_str(self, node):
        toc_bytes = self._filereader.get_node_bytes(node)
        toc_str = toc_bytes.decode("utf-8", errors="replace")
        return toc_str
        
    def filter_toc_nodes(self, nodes):
        tocs = []
        for node in nodes:
            node:Node
            if node.get_inode() is None and node.get_size() is None:
                continue
            if node.get_name():
                if node.get_name()[-3:].lower() == "toc" and node.get_file_ext() == ".txt":
                    tocs.append(node)
        Logger.log(f"Unreal Analyzer: Identified {len(tocs)} tocs to analyze.")
        return tocs
    
    def parse_toc_nodes(self, toc_nodes):
        utocs = []
        for node in toc_nodes:
            toc_string = self.parse_toc_node_to_str(node)
            toc = UnrealTOC(node, toc_string)
            utocs.append(toc)
        return utocs

    def search_for_file_matches(self):
        for toc in self.unreal_tocs:
            toc:UnrealTOC
            for unode in toc.unreal_nodes:
                unode:UnrealNode
                if unode.get_type() == NodeType.FILE:
                    if unode.toc_entry.md5:
                        if self._md5_node_map is None:
                            self.generate_node_md5_hashes()
                        if unode.toc_entry.md5 in self._md5_node_map:
                            Logger.log(f"Unreal Analyzer: MD5 match found for file: {unode.get_name()}")
                            unode.set_matched_node(self._md5_node_map.get(unode.toc_entry.md5))
                    else:
                        # TODO: Figure out how I want to do file size matches
                        pass
                        # if self._size_node_map is None:
                        #     self.generate_node_size_map()
                        # if unode.get_size() in self._size_node_map:
                        #     size_matches =  self._size_node_map.get(unode.get_size())
                        #     for node in size_matches:
                        #         node:Node
                        #         if node.get_name() == unode.get_name():
                        #             Logger.log(f"Unreal Analyzer: Match found based on size + name for file: {unode.get_name()}")
                        #             unode.possible_matched_nodes.append(node)
                        #         elif node.get_direct() is None:
                        #             if node.get_file_ext():
                        #                 if node.get_file_ext().lower() == unode.get_file_ext().lower():
                        #                     Logger.log(f"Unreal Analyzer: Possible match to orphaned inode based on size + extension for file: {unode.get_name()}")
                        #                     unode.possible_matched_nodes.append(node)
                        #             Logger.log(f"Unreal Analyzer: Possible match to orphaned inode based on size for file: {unode.get_name()}")
                        #             unode.possible_matched_nodes.append(node)

    def assign_file_matches(self):
        toc_file_offsets = self.generate_toc_file_offset_map()
        for toc in self.unreal_tocs:
            toc:UnrealTOC
            for unode in toc.unreal_nodes:
                unode:UnrealNode
                if unode._matched_node is None:
                    if len(unode.possible_matched_nodes) > 0:
                        #TODO: Decide how to rank and assign matches
                        pass

    def generate_toc_file_offset_map(self):
        offset_map = {}
        for toc in self.unreal_tocs:
            toc:UnrealTOC
            foffset = toc.toc_node.get_file_offset()
            offset_map[foffset] = toc
        return offset_map
                
    def generate_node_size_map(self):
        Logger.log("Unreal Analyzer: Generating size mapping for all identified files...")
        self._size_node_map = {}
        for node in self._all_nodes:
            node:UnrealNode
            size = node.get_size() 
            if size is not None:
                if size > 0:
                    if size not in self._size_node_map:
                        self._size_node_map[size] = [node]
                    else:
                        self._size_node_map.get(size).append(node)

    def generate_node_md5_hashes(self):
        Logger.log("Unreal Analyzer: Generating md5 mapping for all identified files...")
        self._md5_node_map = {}
        for node in self._all_nodes:
            node:UnrealNode
            if node.get_type() == NodeType.FILE:
                if node.get_size() or node.get_inode():
                    md5 = hashlib.md5(self._filereader.get_node_bytes(node)).hexdigest()
                    Logger.log(f"File: {node.get_name()} MD5: {md5}")
                    self._md5_node_map[md5] = node

    def get_root_unodes(self):
        root_nodes = []
        for utoc in self.unreal_tocs:
            utoc:UnrealTOC
            utoc_root_node = Node(NodeType.DIRECTORY)
            utoc_root_node.set_name(f"UnrealTOC {utoc.toc_node.get_file_offset():X}")
            for unode in utoc.unreal_nodes:
                if len(unode.get_parents()) == 0:
                    if unode.get_type() == NodeType.FILE:
                        utoc_root_node.add_child(unode)
                        unode.add_parent(utoc_root_node)
                    elif len(unode.get_children()) > 0:
                        utoc_root_node.add_child(unode)
                        unode.add_parent(utoc_root_node)
            root_nodes.append(utoc_root_node)
        return root_nodes
