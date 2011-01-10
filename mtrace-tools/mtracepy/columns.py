from util import uhex

#
# Classes to help with reading and printing values from the database.
#
class Address:
    def __init__(self, value, column):
        self.value = value
        self.column = column

    def __str__(self):
        return '%lx' % uhex(self.value)

    @staticmethod
    def create(value, column):
        return Address(value, column)

class Unsigned:
    def __init__(self, value, column):
        self.value = value
        self.column = column

    def __str__(self):
        return str(self.value)

    @staticmethod
    def create(value, column):
        return Unsigned(value, column)

class AccessType:
    def __init__(self, value, column):
        self.value = value
        self.column = column

    def __str__(self):
        accessTypeStrings = {
            1 : 'load',
            2 : 'store',
            3 : 'store'
        }
        return accessTypeStrings[self.value]

    @staticmethod
    def create(value, column):
        return AccessType(value, column)

class LabelString:
    def __init__(self, value, column):
        self.value = value
        self.column = column

    def __str__(self):
        return self.value

    @staticmethod
    def create(value, column):
        return LabelString(value, column)

class ColumnValue:
    def __init__(self, create, column):
        self.column = column
        self.create = create

def create_column_string(columnVals):
    """Return a comma separated string of column names."""
    cols = columnVals[0].column
    for col in columnVals[1:]:
        cols += ',' + col.column
    return cols

def create_column_objects(columnVals, row):
    """Returns an array of objects for each value in row."""
    objects = []
    i = 0
    for val in row:
        objects.append(columnVals[i].create(val, columnVals[i].column))
        i += 1
    return objects

def get_column_object(objects, column):
    for o in objects:
        if o.column == column:
            return o
    raise Exception('%s not found' % column)
