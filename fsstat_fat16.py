# -*- coding: utf-8 -*-
"""
Created on Sat Mar 16 21:56:04 2019

@author: sferg
"""

import struct


def fsstat_fat16(fat16_file, sector_size=512, offset=0):
    result = ['FILE SYSTEM INFORMATION',
              '--------------------------------------------',
              'File System Type: FAT16',
              '']
    data = fat16_file.read()
    if offset > 0:
        data = data[offset*sector_size:]
    sectorsize = get_sector_size(data)
        
    result.append('OEM Name: ' + get_str(data[3:11]))
    result.append('Volume ID: ' + hex(as_le_unsigned(data[39:43])))
    result.append('Volume Label (Boot Sector): ' + get_str(data[43:54]))
    result.append('File System Type Label: ' + get_str(data[54:62]))
    result.append('')
    
    result.append('Sectors before file system: ' + str(offset))
    result.append('')
    
    result.append('File System Layout (in sectors)')
    result.append('Total Range: 0 - ' + str(get_sector_count(data) - 1))
    result.append('* Reserved: 0 - ' + str(get_reserved_area_size(data)//get_sector_size(data) - 1))
    result.append('** Boot Sector: 0')
    result.append('* FAT 0: {} - {}'.format(get_reserved_area_size(data)//sectorsize, \
                  (get_reserved_area_size(data) + get_fat_size(data))//sectorsize - 1))
    if (get_number_of_fats(data) > 1):
        result.append('* FAT 1: {} - {}'.format((get_reserved_area_size(data) + \
                      get_fat_size(data))//sectorsize, (get_reserved_area_size(data) \
                                       + 2*get_fat_size(data))//sectorsize - 1))
    result.append('* Data Area: {} - {}'.format((get_reserved_area_size(data) + \
                  get_number_of_fats(data) * get_fat_size(data))//sectorsize, get_sector_count(data) - 1))
    result.append('** Root Directory: {} - {}'.format((get_reserved_area_size(data) + \
                  get_number_of_fats(data) * get_fat_size(data))//sectorsize, \
    (get_reserved_area_size(data) + get_number_of_fats(data) * get_fat_size(data) + \
     get_max_root_directory_entries(data) * 32)//sectorsize - 1))
     
    cluster_start = (get_reserved_area_size(data) + \
                  get_number_of_fats(data) * get_fat_size(data) \
            + get_max_root_directory_entries(data) * 32)//get_cluster_size(data)
    unused_sectors = get_sector_count(data) - ((get_cluster_num(data) + cluster_start) * (get_cluster_size(data)//sectorsize)) - 1
 
    if (unused_sectors > 0):
        result.append('** Cluster Area: {} - {}'.format((get_reserved_area_size(data) + \
                  get_number_of_fats(data) * get_fat_size(data) \
            + get_max_root_directory_entries(data) * 32)//sectorsize, get_sector_count(data) - unused_sectors - 1))
        result.append('** Non-clustered: {} - {}'.format(get_sector_count(data) - unused_sectors, get_sector_count(data) - 1))
    else:
        result.append('** Cluster Area: {} - {}'.format((get_reserved_area_size(data) + \
                  get_number_of_fats(data) * get_fat_size(data) \
            + get_max_root_directory_entries(data) * 32)//sectorsize, get_sector_count(data) - 1))
    result.append('')
    
    result.append('CONTENT INFORMATION')
    result.append('--------------------------------------------')
    result.append('Sector Size: ' + str(get_sector_size(data)))
    result.append('Cluster Size: ' + str(get_cluster_size(data)))
    cluster_end = 1 + (get_cluster_num(data)) 
    result.append('Total Cluster Range: 2 - ' + str(cluster_end))
    result.append('')
    
    result.append('FAT CONTENTS (in sectors)')
    result.append('--------------------------------------------')
    result.extend(list(dict.fromkeys(parse_fat(data, offset, sector_size))))
    
    return result

def get_str(fs_bytes):
    str = ''
    i = 0
    while i < len(fs_bytes) and fs_bytes[i] != 0:
        str += chr(fs_bytes[i])
        i += 1
    return str

def as_le_unsigned(b):
    table = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    return struct.unpack('<' + table[len(b)], b)[0]


def get_sector_size(fs_bytes):
    return as_le_unsigned(fs_bytes[11:13])


def get_cluster_size(fs_bytes):
    return as_le_unsigned(fs_bytes[13:14]) * get_sector_size(fs_bytes)


def get_reserved_area_size(fs_bytes):
    return as_le_unsigned(fs_bytes[14:16]) * get_sector_size(fs_bytes)


def get_fat_size(fs_bytes):
    return as_le_unsigned(fs_bytes[22:24]) * get_sector_size(fs_bytes)


def get_fat0(fs_bytes):
    start = get_reserved_area_size(fs_bytes)
    length = get_fat_size(fs_bytes)
    return fs_bytes[start:start + length]


def get_number_of_fats(fs_bytes):
    return as_le_unsigned(fs_bytes[16:17])


def get_max_root_directory_entries(fs_bytes):
    return as_le_unsigned(fs_bytes[17:19])


def get_root_directory_area(fs_bytes):
    start = get_reserved_area_size(fs_bytes) + get_number_of_fats(fs_bytes) * get_fat_size(fs_bytes)
    length = get_max_root_directory_entries(fs_bytes) * 32  # 32 bytes / entry
    return fs_bytes[start:start + length]


def get_sector_count(fs_bytes):
    return max(as_le_unsigned(fs_bytes[19:21]), as_le_unsigned(fs_bytes[32:36]))


def get_cluster_area(fs_bytes):
    fs_size = get_sector_count(fs_bytes) * get_sector_size(fs_bytes)

    start = get_reserved_area_size(fs_bytes) + get_number_of_fats(fs_bytes) * get_fat_size(fs_bytes) \
            + get_max_root_directory_entries(fs_bytes) * 32

    number_of_clusters = (fs_size - start) // get_cluster_size(fs_bytes)
    length = number_of_clusters * get_cluster_size(fs_bytes)

    return fs_bytes[start:start + length]

def get_cluster_num(fs_bytes):
    fs_size = get_sector_count(fs_bytes) * get_sector_size(fs_bytes)

    start = get_reserved_area_size(fs_bytes) + get_number_of_fats(fs_bytes) * get_fat_size(fs_bytes) \
            + get_max_root_directory_entries(fs_bytes) * 32

    number_of_clusters = (fs_size - start) // get_cluster_size(fs_bytes)

    return number_of_clusters


def get_filename(dirent):
    return dirent[0:8].decode('ascii').strip() + '.' + dirent[8:11].decode('ascii')


def get_first_cluster(dirent):
    return as_le_unsigned(dirent[26:28])


def get_filesize(dirent):
    return as_le_unsigned(dirent[28:32])


def get_cluster_numbers(first_cluster, fat_bytes, cluster_size):
    result = [first_cluster]
    offset = 2 * first_cluster
    next_cluster = as_le_unsigned(fat_bytes[offset:offset + 2])
    while next_cluster < as_le_unsigned(b'\xf8\xff'):
        if offset//2 + 1 != next_cluster:
            result.append(offset//2)
            result.append(next_cluster)
        if as_le_unsigned(fat_bytes[2*next_cluster:2*next_cluster + 2]) >= as_le_unsigned(b'\xf8\xff'): 
            result.append(next_cluster)
        offset = 2 * next_cluster
        next_cluster = as_le_unsigned(fat_bytes[offset:offset + 2])
    return result

def parse_fat(data, offset, sector_size):
    result = []
    root_dir = get_root_directory_area(data)
    cluster_start = (get_reserved_area_size(data) + \
                  get_number_of_fats(data) * get_fat_size(data) \
            + get_max_root_directory_entries(data) * 32)//get_sector_size(data)
    i = 0
    entry = root_dir[32:65]
    
    while  i//32 < get_max_root_directory_entries(data):
        if as_le_unsigned(entry[0:1]) == 0 or entry[11] == 0x0f:
            i += 32
            entry = root_dir[i:i+33]
        else:
            first_cluster = as_le_unsigned(entry[26:28])
            #print(entry)
            cluster_run = get_cluster_numbers(first_cluster, get_fat0(data), get_cluster_size(data))
            #print(cluster_run)
            cluster_run_parsed = parse_cluster_run(cluster_run, cluster_start, get_cluster_size(data), get_sector_size(data))
            #print('parsed: ', cluster_run_parsed)
            result.extend(cluster_run_parsed)

            i += 32
            entry = root_dir[i:i + 33]
            
    return result

def parse_cluster_run(cluster_run, cluster_start, cluster_size, sector_size):
    result = []
    
    if len(cluster_run) <= 3:
        start = (cluster_run[0] - 2) * (cluster_size//sector_size) + cluster_start
        end = (cluster_run[-1] - 2) * (cluster_size//sector_size) + cluster_start + 1
        num_sectors = end - start + 1
        result.append('{}-{} ({}) -> {}'.format(str(start), str(end), str(num_sectors), 'EOF'))
    else:
        for i in range(0, len(cluster_run)//3 + 1, 1):
            if i < len(cluster_run)//3:
                start = (cluster_run[i] - 2) * (cluster_size//sector_size) + cluster_start
                end = (cluster_run[i + 1] - 2) * (cluster_size//sector_size) + cluster_start + 1
                _next = (cluster_run[i + 2] - 2) * (cluster_size//sector_size) + cluster_start
                num_sectors = end - start + 1
                result.append('{}-{} ({}) -> {}'.format(str(start), str(end), str(num_sectors), str(_next)))
            else:
                start = (cluster_run[-2] - 2) * (cluster_size//sector_size) + cluster_start
                end = (cluster_run[-1] - 2) * (cluster_size//sector_size) + cluster_start + 1
                num_sectors = end- start + 1
                result.append('{}-{} ({}) -> {}'.format(str(start), str(end), str(num_sectors), 'EOF'))
                
    return result
    

     

    
    
    