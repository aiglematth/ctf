SECTIONS {

    .text(0x555555554000) : {
        KEY               = 0x5030;
        IV                = 0x5040;
        RAM_CONTENT       = 0x5050;
        RAM_CONTENT_INDEX = 0x5058;
        RAM_ID            = 0x505c;
        LOCK              = 0x5060;
        RAM_INIT_CHUNK    = 0x5090;

        main                        = 0x1d5f;
        accept_clients              = 0x287d;
        command_0_send_informations = 0x26e9;
        command_RAM_available_size  = 0x25e4;
        command_RAM_decrypt         = 0x1f9e;
        command_RAM_encrypt         = 0x226d;
        command_RAM_free            = 0x1ef0;
        command_RAM_free_all        = 0x2572;
        command_RAM_malloc          = 0x1daf;
        command_RAM_unfragment      = 0x2677;
        AES_decrypt                 = 0x1c4b;
        AES_encrypt                 = 0x1b37;
        init_mem                    = 0x1549;
        mul_by_0xdeabbeef           = 0x1b1b;
        RAM_available_size          = 0x19cf;
        RAM_decrypt                 = 0x17d6;
        RAM_encrypt                 = 0x1862;
        RAM_free                    = 0x1717;
        RAM_free_all                = 0x18d4;
        RAM_get                     = 0x1ab4;
        RAM_malloc                  = 0x15cc;
        RAM_unfragment              = 0x19a5;
        RAM_unk                     = 0x1a4c;
        send_int                    = 0x1d82;
        treat_client                = 0x2a77;
        treat_client_command        = 0x27ca;    
    }

}