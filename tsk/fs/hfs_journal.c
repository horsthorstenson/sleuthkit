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
 * Process the Journal Info Block
 */ 

static TSK_WALK_RET_ENUM  load_jinfoblock_action (const TSK_FS_BLOCK *
								a_block, void *a_ptr)
{		
						
		TSK_FS_INFO * fs = a_block->fs_info;
		HFS_INFO * hfs = (HFS_INFO *) fs;
		HFS_JINFO * jinfo  = hfs->jinfo;
		
		hfs_journ_sb * j_sb = (hfs_journ_sb *)a_block->buf;
		
		jinfo->j_inum = tsk_getu64(fs->endian, j_sb->offs)/fs->block_size;
		jinfo->journal_size = tsk_getu64(fs->endian, j_sb->size);   
				
		//memcpy(a_ptr, a_block->buf, sizeof(hfs_journ_sb));
				
		return TSK_WALK_STOP;	
}

/*
 *  Print selected Journal Block to STDOUT
 */ 
 
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

/*
 *  Load the Journal Buffer into own Buffer with beginning at start
 *  block and skipping the Journal Header.
 */ 

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
			//this should not happen
			return 	TSK_WALK_ERROR;
		}
		return TSK_WALK_CONT; 
}								



/*
 * Note: Everything in the .journal file is stored in 
 * Little Endian intsead of Big Endian (fs->endian). 
 */

static TSK_WALK_RET_ENUM  load_jheader_action (const TSK_FS_BLOCK *
								a_block, void *a_ptr)
{
		hfs_journal_header * jheader = (hfs_journal_header*)a_block->buf;	
				
		TSK_FS_INFO * fs = a_block->fs_info;
		HFS_INFO * hfs = (HFS_INFO *) fs;
		HFS_JINFO * jinfo  = hfs->jinfo;
		
		TSK_ENDIAN_ENUM j_endian = TSK_LIT_ENDIAN;
		
		// clean up any error messages that are lying around
		tsk_error_reset();
				
		/*
		 * test if journal size value from Journal header has the same 
		 * size as the value from Journal Info Block
		 */ 
				
		if(tsk_getu64(j_endian,jheader->size) != jinfo->journal_size)
		{
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
			tsk_error_set_errstr("ERROR: Journal size should be: %"PRIu64 
			" from Journal Info Block, but is: %" PRIu64 
			" from Journal Header", jinfo->journal_size, 
			tsk_getu64(j_endian,jheader->size));
			return TSK_WALK_ERROR;
		}
				
		/*
		 *  test if the checksum is right
		 */ 
		
		uint32_t checksum = tsk_getu32(j_endian, jheader->checksum);
				
		for(int i = 0; i < 4 ; i++){
			jheader->checksum[i] = 0;
		}		
		if(checksum != hfs_calc_checksum((unsigned char *)jheader, 
										sizeof(hfs_journal_header))){
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
			tsk_error_set_errstr("ERROR: Journal Header checksum is wrong");
			return TSK_WALK_ERROR;
		}
			
		/*
		 * fill JINFO struct 
		 */ 
			
		jinfo->journal_size = tsk_getu64(j_endian,jheader->size);
		jinfo->start = tsk_getu64(j_endian, jheader->start);
		jinfo->end = tsk_getu64(j_endian, jheader->end);
		jinfo->blhdr_size = tsk_getu32(j_endian,jheader->blhdr_size);
		jinfo->jhdr_size = tsk_getu32(j_endian,jheader->jhdr_size);
			
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
	if(fs->journ_inum != inum){
		tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Journal inum is unclear");
		return 1;
	}
		
	hfs->jinfo = jinfo = (HFS_JINFO *) tsk_malloc(sizeof(HFS_JINFO));
    if (jinfo == NULL) {
        return 1;
    }
	
	// clean up any error messages that are lying around
    tsk_error_reset();
	
        
    
    /*
     * Read the Journal Info Block at inum to get .journal block number
     */     
      
    if(tsk_fs_block_walk(fs, inum, inum, TSK_FS_BLOCK_WALK_FLAG_ALLOC, 
										load_jinfoblock_action, NULL)){
		tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error loading Journal Info Block");
        return 1;
    }
    
    /*
     * Read the Journal Block to fill the JINFO struct
     */     
    		
    if(tsk_fs_block_walk(fs, jinfo->j_inum, jinfo->j_inum, 
       TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jheader_action, NULL)){
        //Error msg was set in load_jheader_action
        return 1;
    }   
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


    if ((jinfo == NULL) || (hfs == NULL)){
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
		
	TSK_DADDR_T start = jinfo->start / fs->block_size + jinfo->j_inum;
	TSK_DADDR_T end = (jinfo->j_inum + (jinfo->journal_size/
							fs->block_size)) -1;
	
	
	if(tsk_fs_block_walk(fs, start, end, TSK_FS_BLOCK_WALK_FLAG_ALLOC,
								load_jloader_action, (void *) buffer)){
		tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error loading Journal into buffer");
        return 1;
	}
	
	if(tsk_fs_block_walk(fs, jinfo->j_inum, start-1,
	TSK_FS_BLOCK_WALK_FLAG_ALLOC, load_jloader_action, (void *) buffer))
	{
		tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error loading Journal into buffer");
        return 1;
	}
	
	
	uint64_t real_offset = 0;
	uint32_t blocksize = fs->block_size;
	uint32_t blocknumber = 0;
	uint64_t start_block_offset = jinfo->start % blocksize;
	uint32_t block_offset = 0;
	
	uint64_t offset = 0;
	uint32_t trans_count = 0; 
	uint16_t active;
	uint16_t blocks = 0;
	int64_t bytes_left = 0;
	
	j_block_list_header * cur_header= (j_block_list_header *) &buffer[0];
	
	/* 
	 * Process the journal   つ ◕_◕ ༽つ
     */
        
    tsk_printf("JBlk\t\tDescription\n");
    	
	
	while(offset < (jinfo->journal_size-jinfo->jhdr_size)){
					
			
		//calculate the intern block number
		if(offset < jinfo->journal_size - jinfo->start){
			blocknumber = (offset + jinfo->start) / blocksize;	
		}else{
			blocknumber = ((offset-(jinfo->journal_size - 
					        jinfo->start-jinfo->jhdr_size))/blocksize);			        
		}
		if((blocknumber % (jinfo->journal_size / blocksize))==0){
					blocknumber = 0;
		}
		
				
		//calculate header offset in block 
		if(offset <= jinfo->journal_size - jinfo->start){
			block_offset = (offset+start_block_offset) % blocksize; 
		}else{
			block_offset = (offset+start_block_offset+jinfo->jhdr_size)
														% blocksize; 
		}		
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
		
		// check for Block List Header
		if(hfs_test_checksum_jblock(cur_header))
		{
			//look for next Block List header or print Block as unused
						
			if(offset > jinfo->journal_size ){
				return 0;
			}
			if(block_offset != 0 ){
				tsk_printf("%" PRIuDADDR"(+%"PRIu32"):\t Unused \n",
										blocknumber, block_offset);
			}else{
				tsk_printf("%" PRIuDADDR"\t\t Unused \n", blocknumber);
			}			
			
			//check rest of block
			bytes_left = blocksize - block_offset;
			while(bytes_left > 0){
				cur_header = (j_block_list_header *) &buffer[++offset];
				if(!hfs_test_checksum_jblock(cur_header)){
					break;	
				}
				bytes_left--;	
			}
			continue;	
		}
		
		//not enough space for complete transaction
		if(tsk_getu32(0x01, cur_header->bytes_used) > 
										(jinfo->journal_size - offset)){
			
			tsk_fprintf(stderr, "Here is the end!!11 \n\n");			
			bytes_left = jinfo->journal_size - offset;
			while(bytes_left > 0){
				if(block_offset != 0 ){
				tsk_printf("%" PRIuDADDR"(+%"PRIu32"):\t Unused \n",
										blocknumber, block_offset);
				}else{
					tsk_printf("%" PRIuDADDR"\t\t Unused \n", block_offset);
				}
				bytes_left -= blocksize - block_offset;
				if(bytes_left <= 0){
					return 0;
				}
				blocknumber++;
				// end of buffer -> spin
				if((blocknumber % (jinfo->journal_size / blocksize))==0){
					blocknumber = 0;
					block_offset = jinfo->jhdr_size;
				}	
			
			}														
		}
		
		//print blocks containing the journal block header	
		bytes_left = jinfo->blhdr_size;
		while(bytes_left > 0){
			if(block_offset != 0){
				tsk_printf("%" PRIuDADDR 
				"(+%"PRIu32
				"):\t%s Journal Block Header (Transaction: %"PRIu32
				" )\n", blocknumber, block_offset, 
				(!active) ? "active" : "not active",trans_count);
				bytes_left -= blocksize-block_offset;
				block_offset = 0;
			}else{
				tsk_printf("%" PRIuDADDR 
				":\t\t%s Journal Block Header (Transaction: %"PRIu32
				" )\n", blocknumber,
				(!active) ? "active" : "not active", trans_count);
				bytes_left -= blocksize;
			}			
			if(bytes_left >= 0){
				blocknumber++;
			}
			if((blocknumber % (jinfo->journal_size / blocksize))==0){
					blocknumber = 0;
					block_offset = jinfo->jhdr_size;
			}
		}
		
		/*
		 * Go through byte copy actions
		 */
		offset += jinfo->blhdr_size; 
		blocks = tsk_getu16(0x01, cur_header->num_blocks);
		
				
		for(int j = 1; j < blocks; j++){
			bytes_left = (int)tsk_getu32(0x01, cur_header->binfo[j].bsize);
	
			while(bytes_left > 0){
				
				if(offset <= jinfo->journal_size - jinfo->start){
					block_offset = (offset+start_block_offset)
															 %blocksize; 
				}else{
					block_offset = (offset + start_block_offset +
									     jinfo->jhdr_size) % blocksize; 
				}
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
							
				if((blocksize - block_offset) < bytes_left){
					//more than one block	
					offset += (blocksize - block_offset);	
				}else{
					//fits in one block
					offset += bytes_left;	
				}
				bytes_left -= (blocksize - block_offset);
				if(bytes_left < 0){
					//next action
					continue;
				}else{
					blocknumber++;
					if((blocknumber % (jinfo->journal_size
													  /blocksize))==0){
					blocknumber = 0;
					block_offset = jinfo->jhdr_size;
					}
				}							
			}
			
		} 
		
		trans_count++;				
		cur_header = (j_block_list_header *) &buffer[offset];
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
    
    if (end >= last_jblock){
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


