from node import Node
(_ROOT, _DEPTH, _BREADTH) = range(3)

# First commit - jmiller

class Tree:

    def get_paths(self, node, path=None):
        if path is None:
            path = []
        from copy import deepcopy
        pathss = []
        path = deepcopy(path)
        path.append(node.identifier)
        if not node.children:
            pathss.append(path)
        for child in node.children:
            self.get_paths(self, child, path)

    def __init__(self):
        self.__nodes = {}

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
        if depth == _ROOT:
            print("{0}".format(identifier))
        else:
            print("\t" * depth, "{0}".format(identifier))

        depth += 1
        for child in children:
            self.display(child, depth)  # recursive call

    # def path(self, identifier, parents=[], depth=_ROOT):
    # children = self[identifier].children

    # if depth == _ROOT:
    # print("{0}".format(identifier))
    # else:
    # print("\t"*depth, "{0}".format(identifier))
    # #print("\t"*depth, "{0}".format(identifier))

    # #depth += 1
    # parents.append(identifier)
    # for child in children:
    # for parent in parents:
    # print (parent + ' --> ', end='')
    # self.path(child, parents, depth, )  # recursive call
    # parents.pop()

    def paths(self, obj, complete_list=None, path=None):

        def paths_to_list(path_string):

            tmp_list = []
            for item in path_string:
                tmp_list.append(item.split(chr(0)))
            return tmp_list

        if path is None:
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

        return paths_to_list(complete_list)

    def traverse(self, identifier, mode=_DEPTH):
        # Python generator. Loosely based on an algorithm from
        # 'Essential LISP' by John R. Anderson, Albert T. Corbett,
        # and Brian J. Reiser, page 239-241
        yield identifier
        queue = self[identifier].children
        while queue:
            yield queue[0]
            expansion = self[queue[0]].children
            if mode == _DEPTH:
                queue = expansion + queue[1:]  # depth-first
            elif mode == _BREADTH:
                queue = queue[1:] + expansion  # width-first

    def __getitem__(self, key):
        return self.__nodes[key]

    def __setitem__(self, key, item):
        self.__nodes[key] = item

