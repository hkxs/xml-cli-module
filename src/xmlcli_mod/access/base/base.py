import os
import binascii
import configparser

SMI_TRIGGER_PORT = 0xB2
DEPRECATION_WARNINGS = False


class BaseAccess(object):
    def __init__(self, access_name, child_class_directory):
        self.InterfaceType = access_name
        self.interface = access_name
        self.config = configparser.RawConfigParser(allow_no_value=True)
        self.config_file = os.path.join(child_class_directory, "{}.ini".format(access_name))
        self.read_config()

    @staticmethod
    def byte_to_int(data):
        return int(binascii.hexlify(bytearray(data)[::-1]), 16)

    @staticmethod
    def int_to_byte(data, size):
        data_dump = data.to_bytes(size, byteorder="little", signed=False)
        return data_dump

    def read_config(self):
        self.config.read(self.config_file)

    def halt_cpu(self, delay):
        raise NotImplementedError()

    def run_cpu(self):
        raise NotImplementedError()

    def initialize_interface(self):
        raise NotImplementedError()

    def close_interface(self):
        raise NotImplementedError()

    def warm_reset(self):
        raise NotImplementedError()

    def cold_reset(self):
        raise NotImplementedError()

    def mem_block(self, address, size):
        raise NotImplementedError()

    def mem_save(self, filename, address, size):
        raise NotImplementedError()

    def mem_read(self, address, size):
        raise NotImplementedError()

    def mem_write(self, address, size, value):
        raise NotImplementedError()

    def load_data(self, filename, address):
        raise NotImplementedError()

    def read_io(self, address, size):
        raise NotImplementedError()

    def write_io(self, address, size, value):
        raise NotImplementedError()

    def trigger_smi(self, smi_value):
        raise NotImplementedError()

    def read_msr(self, ap, address):
        raise NotImplementedError()

    def write_msr(self, ap, address, value):
        raise NotImplementedError()


    def read_sm_base(self):
        raise NotImplementedError()

    @staticmethod
    def is_thread_alive(thread):
        raise NotImplementedError()
