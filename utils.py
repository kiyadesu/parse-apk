def read_file(file_path, read_size=-1):
    with open(file_path, 'rb') as f:
        return f.read(read_size)
