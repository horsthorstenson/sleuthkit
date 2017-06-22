/*
 * The Sleuth Kit
 * 
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file hfs_journal.c
 * Contains the internal TSK HFS+ journal code -- not included in code by default.
 */
#include "tsk_fs_i.h"
#include "tsk_hfs.h"


uint32_t 
hfs_calc_checksum (unsigned char* ptr, uint64_t len)
{	
	uint64_t i, cksum=0;
    for(i=0; i < len; i++, ptr++) {
        cksum = (cksum << 8) ^ (cksum + *ptr);
    }
    return (~cksum);
}

uint32_t
hfs_test_checksum_jblock(j_block_list_header* ptr)
{
	uint32_t checksum = tsk_getu32(0x01, ptr->checksum);
	uint8_t temp [4];
		
	for(int i = 0; i < 4 ; i++){
		temp[i] = ptr->checksum[i];
		ptr->checksum[i] = 0;
	}
		
    if(checksum == hfs_calc_checksum((unsigned char *)ptr, 
										sizeof(j_block_list_header))){
			for(int i = 0; i < 4 ; i++){
				ptr->checksum[i] = temp[i];
			}
			return 0;
	}else{
			for(int i = 0; i < 4 ; i++){
				ptr->checksum[i] = temp[i];
			}			
			return 1;
	}					
}

/*
void hfs_hex_print(char* inp, unsigned int len)
{
	tsk_fprintf(stderr, "\n ------------------------------------- \n");
	tsk_fprintf(stderr, "Offset \t data \n");
	for(int i = 0; i < len; i++){
		if(i % 32 == 0){
		tsk_fprintf(stderr,"\n %u: \t \t ", i);
		}
		tsk_fprintf(stderr," %x ", inp[i]);
	}
}


void hfs_hex_print_j_block_list_header(char* inp)
{
	for(int i = 0; i< sizeof(j_block_list_header);i++){
			
			tsk_fprintf(stderr, "Journal List Header: \n");
			tsk_fprintf(stderr, " %x ", inp[i]);
			if(i == 1 || i == 3 || i == 7 || i == 11 || i == 15 || i == 23 || i == 27 || i == 31){
					tsk_fprintf(stderr, " \n");
				}
	}
	tsk_fprintf(stderr, "----------------------------- \n");
}


*/

static TSK_WALK_RET_ENUM  load_jinfoblock_action (const TSK_FS_BLOCK *
								a_block, void *a_ptr)
{		
						
		memcpy(a_ptr, a_block->buf, sizeof(hfs_journ_sb));
				
		return TSK_WALK_STOP;	
}

static TSK_WALK_RET_ENUM  load_jblockwrite_action (const TSK_FS_BLOCK *
								a_block, void *a_ptr)
{		
						
		//memcpy(a_ptr, a_block->buf, sizeof(hfs_journ_sb));
		char* buffer = (char *) a_block->buf;
		
		if (fwrite(buffer, a_block->fs_info->block_size, 1, stdout) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WRITE);
        tsk_error_set_errstr
            ("hfs_jblk_walk: error writing buffer block(s)");
        free(buffer);
        return 1;
    }
		
				
		return TSK_WALK_STOP;	
}



static TSK_WALK_RET_ENUM  load_jloader_action (const TSK_FS_BLOCK *
								a_block, void *a_ptr)
{
	
						
		TSK_FS_INFO *fs = (TSK_FS_INFO *) a_block->fs_info;
		HFS_INFO *hfs = (HFS_INFO *) fs;
		HFS_JINFO * jinfo  = hfs->jinfo;
		
		char* ptr = (char *) a_ptr;
		uint64_t offset = 0;		
		uint64_t block_off = (a_block->addr - jinfo->j_inum) *
														fs->block_size;											
		
		uint64_t start_off = jinfo->start;		 
		uint64_t buff_end = jinfo->journal_size;
		uint32_t jhdr_size = jinfo->jhdr_size;
										
		uint64_t round_off = ((a_block->addr - hfs->jinfo->j_inum + 1) * 
								fs->block_size) - jhdr_size;
		
					
		//first block
		if((start_off - block_off) < fs->block_size){
			//intern split first block 
			offset = start_off - block_off;
			//copy last part of block to start of buffer
			memcpy(ptr, a_block->buf + offset, fs->block_size - offset);
			uint64_t tempoff = jinfo->journal_size - jinfo->jhdr_size
															- offset;
			ptr = &ptr[tempoff];
			//copy first part of block to end of buffer
			memcpy(ptr, a_block->buf, offset);		
		}else if(block_off >= start_off && block_off <= 
											buff_end - fs->block_size){
			//blocks from start to buffer end
			offset = block_off - start_off;
			ptr = &ptr[offset];
			memcpy(ptr, a_block->buf, fs->block_size);	
		}else if(block_off < start_off){
			//start of buffer to journal start block
			offset = buff_end - start_off;
			uint32_t len = fs->block_size - hfs->jinfo->jhdr_size;		
			if(block_off == 0){			
				//first block in buffer -> skip header
				if(len == 0){
					//block only contains journal header
					return TSK_WALK_CONT;
				}
				ptr = &ptr[offset];
				memcpy(ptr, &a_block->buf[hfs->jinfo->jhdr_size], len);
			}
			else{
				//remaining blocks from buffer start to start block
				offset += (block_off - fs->block_size);
				offset += len;
				ptr = &ptr[offset];
				memcpy(ptr, a_block->buf, fs->block_size);
			}
		}else{
			tsk_printf(stderr, "This should not happen\n");
			return 	TSK_WALK_STOP;
		}
		
		return TSK_WALK_CONT;
		 
}								



/*
 * Note: Everything in the .journal file is stored in 
 * Little Endian intsead of Big Endian (fs-> endian). 
 */

static TSK_WALK_RET_ENUM  load_jheader_action (const TSK_FS_BLOCK *
								a_block, void *a_ptr)
{
		hfs_journal_header * jheader = (hfs_journal_header*)a_block->buf;	
		hfs_journ_sb * j_sb = (hfs_journ_sb *) a_ptr;
		
		TSK_FS_INFO * fs = a_block->fs_info;
		HFS_INFO * hfs = (HFS_INFO *) fs;
		HFS_JINFO * jinfo  = hfs->jinfo;
		
		TSK_ENDIAN_ENUM j_endian = TSK_LIT_ENDIAN;
		
		// clean up any error messages that are lying around
		tsk_error_reset();
				
		
		if(tsk_getu64(fs->endian, j_sb->size) != 
									tsk_getu64(j_endian,jheader->size))
		{
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_MAGIC);
			tsk_fprintf(stderr, "ERROR: size should be jinfo: % " PRIu64 
			" but is jheader:  %" PRIu64 "\n", j_sb->size, 
			jheader->size);
			return TSK_WALK_ERROR;
		}
				
		
		tsk_fprintf(stderr, "size should be jinfo: %" PRIu64 " but is jheader:  %" PRIu64 "\n", 
				tsk_getu64(fs->endian, j_sb->size), tsk_getu64(j_endian,jheader->size));
		
		
		tsk_fprintf(stderr, "Journal Header: \n");
		
		tsk_fprintf(stderr, "magic: %" PRIu32
						"\n", tsk_getu32(j_endian,jheader->magic));
		tsk_fprintf(stderr, "endian: %" PRIu32
						"\n", tsk_getu32(j_endian,jheader->endian));
		tsk_fprintf(stderr, "start: %" PRIu64
						"\n", tsk_getu64(j_endian,jheader->start));
		tsk_fprintf(stderr, "end: %" PRIu64
						"\n", tsk_getu64(j_endian,jheader->end));				
		tsk_fprintf(stderr, "size: %" PRIu64
						"\n", tsk_getu64(j_endian,jheader->size));				
		tsk_fprintf(stderr, "blhdr_size: %" PRIu32
						"\n", tsk_getu32(j_endian,jheader->blhdr_size));				
		tsk_fprintf(stderr, "checkcsum: %" PRIu32
						"\n", tsk_getu32(j_endian,jheader->checksum));				
		tsk_fprintf(stderr, "jhdr:size: %" PRIu32
						"\n", tsk_getu32(j_endian,jheader->jhdr_size));
		
		
		//check checksum
		//Check jhdr_size, should be size of sector
			
		jinfo->journal_size = tsk_getu64(j_endian,jheader->size);
		jinfo->start = tsk_getu64(j_endian, jheader->start);
		jinfo->end = tsk_getu64(j_endian, jheader->end);
		jinfo->blhdr_size = tsk_getu32(j_endian,jheader->blhdr_size);
		jinfo->jhdr_size = tsk_getu32(j_endian,jheader->jhdr_size);
		// check checksum					
								
		jheader->checksum[0] = 0;
		jheader->checksum[1] = 0;
		jheader->checksum[2] = 0;
		jheader->checksum[3] = 0;
		
		unsigned int temp =
			hfs_calc_checksum((unsigned char*)jheader, sizeof(hfs_journal_header));
		
		tsk_fprintf(stderr, "checksum: %u\n", temp);
		
		
		
		return TSK_WALK_STOP;	
}



uint8_t
hfs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    //tsk_fprintf(stderr, "jopen not implemented for HFS yet \n");
	
	HFS_INFO * hfs = (HFS_INFO *) fs;
    HFS_JINFO *jinfo;
	
	if (!fs) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_jopen: fs is null");
        return 1;
    }  
		
	hfs->jinfo = jinfo =
        (HFS_JINFO *) tsk_malloc(sizeof(HFS_JINFO));
    if (jinfo == NULL) {
        return 1;
    }
		 	
	//check for right inum
	if(fs->journ_inum != inum){
		tsk_fprintf(stderr, "This is very bad, maaan! \n");
		return 1;
	}
	
	// clean up any error messages that are lying around
    tsk_error_reset();
	
	unsigned int len = 0;
        
    
    /*
     * Read the Journal Info Block at inum to get .journal block
     */     
        
    hfs_journ_sb * j_sb;
		
	len = sizeof(hfs_journ_sb);
    tsk_fprintf(stderr, "size of journal info block: %d \n", len);
    
    if ((j_sb = (hfs_journ_sb *) tsk_malloc(len)) == NULL) {
        tsk_error_set_errstr2("jopen: malloc of Journal Info Block failed");
        tsk_fprintf(stderr, "jheader malloc failed \n");
        return 0;
    }
       
    if(tsk_fs_block_walk(fs, inum, inum, TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jinfoblock_action, (void *)j_sb)){
		tsk_error_reset();
		//update error?
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error journal info block");
        free(j_sb);
        return 1;
    }
    
    
    //calculate .journal block: byte offset / block size
     
    jinfo->j_inum = ((tsk_getu64(fs->endian, j_sb->offs))/ 
						tsk_getu32(fs->endian,hfs->fs->blk_sz));
		
    if(tsk_fs_block_walk(fs, jinfo->j_inum, jinfo->j_inum, 
       TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jheader_action, (void *)j_sb))
    {
		tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error reading journal header block");
        //tsk_fs_file_close(jinfo->fs_file);
        free(j_sb);
        return 1;
    }
      
    
    free(j_sb);   
    return 0;
}

/*
 * fs->jentry_walk(fs, 0, 0, NULL) 
 */

uint8_t
hfs_jentry_walk(TSK_FS_INFO * fs, int flags, TSK_FS_JENTRY_WALK_CB action,
    void *ptr)
{
    tsk_fprintf(stderr, "jentry_walk start: \n");
	
	HFS_INFO *hfs = (HFS_INFO *) fs;
    HFS_JINFO *jinfo = hfs->jinfo;
        
    // clean up any error messages that are lying around
    tsk_error_reset();


    if ((jinfo == NULL) || (hfs == NULL))
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_jentry_walk: journal is not open");
        return 1;
    }
    							
	
	/*
	 * journal is contigous so copy size bytes from start block in buffer
	 */
	
		
	char * buffer =  (char *) tsk_malloc(jinfo->journal_size - 
													  jinfo->jhdr_size);
    if (buffer == NULL) 
    {
        return 1;
    }
		
	//TSK_DADDR_T start = jinfo->j_inum;
	TSK_DADDR_T start = jinfo->start / fs->block_size + jinfo->j_inum;
	TSK_DADDR_T end = (jinfo->j_inum + (jinfo->journal_size/
							fs->block_size)) -1;
	
	
	if(tsk_fs_block_walk(fs, start, end, 
       TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jloader_action, (void *) buffer))
	{
		tsk_error_reset();
		//update error?
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error loading journal into buffer");
        return 1;
	}
	
	if(tsk_fs_block_walk(fs, jinfo->j_inum, start-1, 
       TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jloader_action, (void *) buffer))
	{
		tsk_error_reset();
		//update error?
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error loading journal into buffer");
        return 1;
	}
	
		
	//fwrite(buffer, jinfo->journal_size-jinfo->jhdr_size, 1, stdout);
	
	
	
	uint64_t real_offset = 0;
	uint32_t blocksize = fs->block_size;
	uint32_t blocknumber = 0;
	uint64_t start_block_offset = jinfo->start % blocksize;
	uint32_t block_offset = 0;
	
	uint64_t offset = 0;
	uint32_t trans_count = 0; 
	uint16_t active;
	uint16_t blocks = 0;
	
	j_block_list_header * cur_header=(j_block_list_header *) &buffer[0];
	
	/* 
	 * Process the journal   つ ◕_◕ ༽つ
     */
        
    tsk_printf("JBlk\t\tDescription\n");
    		
	for(int i = 0; i < (jinfo->jhdr_size)/blocksize; i++){
		tsk_printf("%" PRIuDADDR ":\tJournal Header\n", blocknumber++);
	}
	
	while(offset < jinfo->journal_size){
					
		// check for Block List Header
		if(hfs_test_checksum_jblock(cur_header))
		{
			tsk_fprintf(stderr, "checksum passen nicht, bye ! \n");
			return 1;	
		}
		
		
		//calculate the real block number
		if(offset < jinfo->journal_size - jinfo->start){
			blocknumber = (offset + jinfo->start) / blocksize;	
		}else{
			blocknumber = ((offset-(jinfo->journal_size - 
					        jinfo->start))/blocksize) + jinfo->j_inum;
		}
				
		//calculate header offset in block 
		block_offset = (offset+start_block_offset) % blocksize; 
				
		//check if transaction is active or not active
		if(offset < jinfo->journal_size - jinfo->start){
			real_offset = offset + jinfo->start;
		}else{
			real_offset = jinfo->j_inum * blocksize + offset + 
													jinfo->jhdr_size;
		}		 
		if(jinfo->start < jinfo->end){
			if(jinfo->start <= real_offset && real_offset < jinfo->end)
				active = 0;
			else
				active = 1;		
		}else if(jinfo->start > jinfo->end){
			if(real_offset < jinfo->end || real_offset >= jinfo->start)
				active = 0;
			else
				active = 1;
		}else
				active = 1;	
		
		//print blocks containing the journal block header	
		for(int j = 0; j < jinfo->blhdr_size/blocksize; j++){
			if(block_offset != 0 && j == 0){
				tsk_printf("%" PRIuDADDR 
				"(+%"PRIu32
				"):\t%s Journal Block Header (Transaction: %"PRIu32
				" )\n", blocknumber++, block_offset, 
				(!active) ? "active" : "not active",trans_count);
			}else{
				tsk_printf("%" PRIuDADDR 
				":\t\t%s Journal Block Header (Transaction: %"PRIu32
				" )\n", blocknumber++,
				(!active) ? "active" : "not active", trans_count);
			}
		}
		
		/*
		 * Go through byte copy actions
		 */
		offset += jinfo->blhdr_size; 
		blocks = tsk_getu16(0x01, cur_header->num_blocks);
		int temp_size = 0;
				
		for(int j = 1; j < blocks; j++){
			temp_size = (int)tsk_getu32(0x01, cur_header->binfo[j].bsize);
	
			while(temp_size >= 0){
				block_offset = (offset+start_block_offset) % blocksize;
				
				if(block_offset != 0){
					tsk_printf("%" PRIuDADDR 
					"(+%"PRIu32
					"):\t%s write to sector: %"PRIu64
					"\n", blocknumber, block_offset, 
					(!active) ? "active" : "not active",
					tsk_getu64(0x01, cur_header->binfo[j].bnum));
				}else{
					tsk_printf("%" PRIuDADDR 
					":\t\t%s write to sector: %"PRIu64
					"\n", blocknumber, 
					(!active) ? "active" : "not active",
					tsk_getu64(0x01, cur_header->binfo[j].bnum));
				}
															
				//int test = blocksize -block_offset - temp_size;
				//if((test) < 0){
				
				if((blocksize - block_offset) < temp_size){
					//more than one block
					if(block_offset != 0){
						temp_size -= (blocksize - block_offset);
						offset += (blocksize - block_offset);	
					}else{
						temp_size -= blocksize;
						offset += blocksize;						
					}
				}else{
					//fits in one block
					offset += temp_size;
					temp_size = -1;	
				}
				if(temp_size < 0){
					//next action
					continue;
				}else{
					blocknumber++;
				}							
			}
			
		} 
		
		trans_count++;
		tsk_fprintf(stderr, "new offset: %d", offset);					
		cur_header = &buffer[offset];
	}
	
    return 0;
}

uint8_t
hfs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int flags, TSK_FS_JBLK_WALK_CB action, void *ptr)
{
			
	HFS_INFO *hfs = (HFS_INFO *) fs;
    HFS_JINFO *jinfo = hfs->jinfo;
    
    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((jinfo == NULL) || hfs== NULL)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_jblk_walk: journal is not open");
        return 1;
    }

    if (start != end) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("h2fs_jblk_walk: only one block at a time is supported");
        return 1;
    }
    
    if (start < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("hfs_jblk_walk: start block number is negative");
        return 1;
    }
    
    int last_jblock = (jinfo->journal_size / fs->block_size);
    
    if (end > last_jblock){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("hfs_jblk_walk: end block number is too big");
        return 1;
    }
    
    //set start and end to real block number.	
	start += jinfo->j_inum;
	end += jinfo->j_inum;
	
	
	if(tsk_fs_block_walk(fs, start, end, 
       TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jblockwrite_action, NULL))
	{
		tsk_error_reset();
		//update error?
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error writing journal block to stdout");
        return 1;
	}
	
	
    return 0;
}

void printf_jblockheader(j_block_list_header * inp, int count){
	
		uint16_t blocks = tsk_getu16(0x01, inp->num_blocks);
		uint32_t size = 0;
		tsk_fprintf(stderr,"Hallo, : %d", blocks); 
		
		for(int j = 1; j < blocks; j++){
			
			size = tsk_getu32(0x01, inp->binfo[j].bsize);
			tsk_fprintf("Trans %d: Write %"PRIu32" bytes to sector %"PRIu64
						"\n", count, size, tsk_getu64(0x01, inp->binfo[j].bnum));
		}
}

