class NoMaskFoundError(Exception):
    pass

class BadMaskFoundError(Exception):
    def __init__(self, mask=None):
        self.mask = mask

class NoSlotFoundError(Exception):
    pass
