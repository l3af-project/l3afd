package libxdp

import (
	 bpf "github.com/aquasecurity/tracee/libbpfgo"
	"fmt"
)
const XDP_RUN_CONFIG_SEC = ".xdp_run_config"
const XDP_SKIP_ENVVAR = "LIBXDP_SKIP_DISPATCHER"

/* When cloning BPF fds, we want to make sure they don't end up as any of the
 * standard stdin, stderr, stdout descriptors: fd 0 can confuse the kernel, and
 * there are orchestration systems that will force-close the others if they
 * don't point to the "right" things. So just to be safe, use 3 as the minimum
 * fd number.
 */
const MIN_FD = 3
const MAX_RETRY = 10
const IFINDEX_LO = 1
const dispatcher_feature_err = `
 "This means that the kernel does not support the features needed\n"
	"by the multiprog dispatcher, either because it is too old entirely,\n"
	"or because it is not yet supported on the current architecture.\n";`

type xdp_program {
	  /* one of prog or prog_fd should be set */
		bpf_program  *bpf.BPFProg
		struct bpf_object *bpf_obj;
		struct btf *btf;
		enum bpf_prog_type prog_type;
		prog_fd       int
	  link_fd       int
	  prog_name     string
	  attach_name   string
		prog_tag    [BPF_TAG_SIZE]int8
	  prog_id       int32
	  load_time     int64
		from_external_obj bool
    is_frags          bool
	  run_prio          uint
	  chain_call_actions uint; /* bitmap */
	/* for building list of attached programs to multiprog */
	struct xdp_program *next;
}

type xdp_multiprog {
	config xdp_dispatcher_config 
	*main_prog xdp_program
	*first_prog xdp_program
	*hw_prog    xdp_program
	version     uint32
	num_links   size_t
	is_loaded   bool
	is_legacy   bool
	kernel_frags_support bool
	checked_compat bool
	enum xdp_attach_mode attach_mode
  ifindex int
}

const XDP_DISPATCHER_VERSION_V1 = 1

type xdp_dispatcher_config_v1 {
	num_progs_enabled int8             /* Number of active program slots */
	chain_call_actions  [MAX_DISPATCHER_ACTIONS]int32
	run_prios           [MAX_DISPATCHER_ACTIONS];
}

const xdp_action_names[] = {
	[XDP_ABORTED] = "XDP_ABORTED",
	[XDP_DROP] = "XDP_DROP",
	[XDP_PASS] = "XDP_PASS",
	[XDP_TX] = "XDP_TX",
	[XDP_REDIRECT] = "XDP_REDIRECT",
};

func xdp_program__create_from_obj(struct bpf_object *obj,
							section_name string,
							prog_name string,
							external bool) *xdp_program;

#ifdef LIBXDP_STATIC
struct xdp_embedded_obj {
	const char *filename;
	const void *data_start;
	const void *data_end;
};

_binary_xdp_dispatcher_o_start byte;
_binary_xdp_dispatcher_o_end byte;
_binary_xsk_def_xdp_prog_o_start byte;
_binary_xsk_def_xdp_prog_o_end byte;
_binary_xsk_def_xdp_prog_5_3_o_start byte;
_binary_xsk_def_xdp_prog_5_3_o_end byte;

static struct xdp_embedded_obj embedded_objs[] = {
	{"xdp-dispatcher.o", &_binary_xdp_dispatcher_o_start, &_binary_xdp_dispatcher_o_end},
	{"xsk_def_xdp_prog.o", &_binary_xsk_def_xdp_prog_o_start, &_binary_xsk_def_xdp_prog_o_end},
	{"xsk_def_xdp_prog_5.3.o", &_binary_xsk_def_xdp_prog_5_3_o_start, &_binary_xsk_def_xdp_prog_5_3_o_end},
	{},
};

func xdp_program xdp_program__find_embedded(filename string,
						      section_name string,
						      prog_name string,
						      opts *bpf_object_open_opts) *xdp_program
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, default_opts,
		.object_name = filename,
	);
	struct xdp_embedded_obj *eobj;
	struct bpf_object *obj;
	size_t size;
	int err;

	for (eobj = &embedded_objs[0]; eobj->filename; eobj++) {
		if (strcmp(filename, eobj->filename))
			continue;

		size = eobj->data_end - eobj->data_start;

		/* set the object name to the same as if we opened the file from
		 * the filesystem
		 */
		if (!opts)
			opts = &default_opts;
		else if (!opts->object_name)
			opts->object_name = filename;

		pr_debug("Loading XDP program '%s' from embedded object file\n", filename);

		obj = bpf_object__open_mem(eobj->data_start, size, opts);
		err = libbpf_get_error(obj);
		if (err)
			return ERR_PTR(err);
		return xdp_program__create_from_obj(obj, section_name, prog_name, false);
	}

	return NULL;
}
func main() {
	fmt.Println("libxdp")
}
