import csv
import struct

# Define the C structures as Python classes
class IMAGE_VALIDATION_DATA_HEADER:
    def __init__(self):
        self.HeaderSignature = 0x12345678
        self.Size = 0
        self.EntryCount = 0
        self.OffsetToFirstEntry = 0
        self.OffsetToFirstDefault = 0

class IMAGE_VALIDATION_ENTRY_HEADER:
    def __init__(self):
        self.EntrySignature = 0x87654321
        self.Offset = 0
        self.Size = 0
        self.ValidationType = 0
        self.OffsetToDefault = 0

class IMAGE_VALIDATION_DATA_TEST:
    def __init__(self):
        self.Header = IMAGE_VALIDATION_DATA_HEADER()
        self.Entries = []

    def pack(self):
        # Pack the data into a binary blob
        blob = struct.pack('<IIIII', self.Header.HeaderSignature, self.Header.Size,
                           self.Header.EntryCount, self.Header.OffsetToFirstEntry,
                           self.Header.OffsetToFirstDefault)
        for entry in self.Entries:
            blob += struct.pack('<IIIII', entry.EntrySignature, entry.Offset, entry.Size,
                                entry.ValidationType, entry.OffsetToDefault)
        return blob

# Create an instance of the test data structure
data = IMAGE_VALIDATION_DATA_TEST()
data.Header.Size = 24
data.Header.EntryCount = 0
data.Header.OffsetToFirstEntry = 0
data.Header.OffsetToFirstDefault = 0

rawdata = bytearray()

# Read the entries from the CSV file
offset = 0x14 + 0x14 * 46
with open('entries.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        entry = IMAGE_VALIDATION_ENTRY_HEADER()
        entry.Offset = int(row[0], base=0)
        entry.Size = int(row[1], base=0)
        entry.ValidationType = int(row[2], base=0)
        entry.OffsetToDefault = offset
        offset += entry.Size
        data.Entries.append(entry)
        data.Header.EntryCount += 1

        rawdata.extend(bytearray([0] * entry.Size))

# Generate the binary blob
blob = data.pack()

# Save the binary blob to a file
with open('output.bin', 'wb') as f:
    f.write(blob)
    f.write(rawdata)
