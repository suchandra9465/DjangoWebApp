import Node


class Tree:

    def __init__(self):
        self.__nodes = {}
        (_ROOT, _DEPTH, _BREADTH) = range(3)

    @property
    def nodes(self):
        return self.__nodes

    def add_node(self, identifier, parent=None):
        node = Node(identifier)
        self[identifier] = node

        if parent is not None:
            self[parent].add_child(identifier)

        return node

    def display(self, identifier, depth=_ROOT):
        children = self[identifier].children
        if depth == self._ROOT:
            print("{0}".format(identifier))
        else:
            print("\t" * depth, "{0}".format(identifier))

        depth += 1
        for child in children:
            self.display(child, depth)  # recursive call

    def paths(self, obj, complete_list=None, path=None):

        def paths_to_list(path_string):

            tmp_list = []
            for item in path_string:
                tmp_list.append(item.split(chr(0)))
            return tmp_list;

        if path == None:
            path = ''
            complete_list = []
        children = self[obj].children
        if path == '':
            path = obj
        else:
            path = path + chr(0) + obj
        for child in children:
            # path = path + "/"
            self.paths(child, complete_list, path)
        complete_list.append(path)

        return paths_to_list(complete_list);

    def traverse(self, identifier, mode=self._DEPTH):
        # Python generator. Loosly based on an algorithm from
        # 'Essential LISP' by John R. Anderson, Albert T. Corbett,
        # and Brian J. Reiser, page 239-241
        yield identifier
        queue = self[identifier].children
        while queue:
            yield queue[0]
            expansion = self[queue[0]].children
            if mode == self._DEPTH:
                queue = expansion + queue[1:]  # depth-first
            elif mode == self._BREADTH:
                queue = queue[1:] + expansion  # width-first

    def get_paths(self, node, path=[]):
        from copy import deepcopy
        path = deepcopy(path)
        path.append(node.identifier)
        if not node.children:
            pathss.append(path)
        for child in node.children:
            self.__get_paths(child, path)

    def __getitem__(self, key):
        return self.__nodes[key]

    def __setitem__(self, key, item):
        self.__nodes[key] = item
