#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

static inline uint16_t bswap16(uint16_t x)
{
    return (((x & 0x00ff) << 8) |
            ((x & 0xff00) >> 8));
}

static inline uint32_t bswap32(uint32_t x)
{
    return (((x & 0x000000ffU) << 24) |
            ((x & 0x0000ff00U) <<  8) |
            ((x & 0x00ff0000U) >>  8) |
            ((x & 0xff000000U) >> 24));
}

static inline uint64_t bswap64(uint64_t x)
{
    return (((x & 0x00000000000000ffULL) << 56) |
            ((x & 0x000000000000ff00ULL) << 40) |
            ((x & 0x0000000000ff0000ULL) << 24) |
            ((x & 0x00000000ff000000ULL) <<  8) |
            ((x & 0x000000ff00000000ULL) >>  8) |
            ((x & 0x0000ff0000000000ULL) >> 24) |
            ((x & 0x00ff000000000000ULL) >> 40) |
            ((x & 0xff00000000000000ULL) >> 56));
}

static inline void bswap16s(uint16_t *s)
{
    *s = bswap16(*s);
}

static inline void bswap32s(uint32_t *s)
{
    *s = bswap32(*s);
}

static inline void bswap64s(uint64_t *s)
{
    *s = bswap64(*s);
}

#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)

#if defined(HOST_WORDS_BIGENDIAN)
#define be_bswap(v, size) (v)
#define le_bswap(v, size) glue(bswap, size)(v)
#define be_bswaps(v, size)
#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
#else
#define le_bswap(v, size) (v)
#define be_bswap(v, size) glue(bswap, size)(v)
#define le_bswaps(v, size)
#define be_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
#endif

#define CPU_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline void endian ## size ## _to_cpus(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline void cpu_to_ ## endian ## size ## s(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}

CPU_CONVERT(be, 16, uint16_t)
CPU_CONVERT(be, 32, uint32_t)
CPU_CONVERT(be, 64, uint64_t)

CPU_CONVERT(le, 16, uint16_t)
CPU_CONVERT(le, 32, uint32_t)
CPU_CONVERT(le, 64, uint64_t)




typedef struct QCowHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size; /* in bytes */
    uint32_t crypt_method;
    uint32_t l1_size; /* XXX: save number of clusters instead ? */
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;

    /* The following fields are only valid for version >= 3 */
    uint64_t incompatible_features;
    uint64_t compatible_features;
    uint64_t autoclear_features;

    uint32_t refcount_order;
    uint32_t header_length;

    /* Additional fields */
    uint8_t compression_type;

    /* header must be a multiple of 8 */
    uint8_t padding[7];

} __attribute__((packed)) QCowHeader;

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)


/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW_OFLAG_COPIED     (1ULL << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW_OFLAG_COMPRESSED (1ULL << 62)
/* The cluster reads as all zeros */
#define QCOW_OFLAG_ZERO (1ULL << 0)


#define L2E_SIZE_NORMAL   (sizeof(uint64_t))
#define L1E_SIZE (sizeof(uint64_t))
#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21

#define L1E_OFFSET_MASK 0x00fffffffffffe00ULL
#define L2E_OFFSET_MASK 0x00fffffffffffe00ULL


struct qcow2_s {
    QCowHeader hdr;
    int fd;
    size_t file_size;
    size_t cluster_size;

    uint64_t *l1_table;
    uint64_t *reftable;
};

static uint64_t
qcow2_alloc_cluster(struct qcow2_s *s) {
  uint64_t ret = s->file_size;
  s->file_size += s->cluster_size;
  assert(0 == ftruncate(s->fd, s->file_size));
  return ret;
}

static uint64_t
qcow2_refcount(struct qcow2_s *s, uint64_t file_ofst) {
}

static void
qcow2_refcount_add1(struct qcow2_s *s, uint64_t file_ofst) {
}

static void
qcow2_refcount_minus1(struct qcow2_s *s, uint64_t file_ofst) {

}

static uint64_t
qcow2_get_l2_entry(struct qcow2_s *s, uint64_t l2_table_off,
		   uint64_t l2_index) {
    uint64_t the_l2_entry;
    assert(L2E_SIZE_NORMAL ==
	   pread(s->fd, &the_l2_entry, L2E_SIZE_NORMAL,
		 l2_table_off + l2_index * L2E_SIZE_NORMAL));
    return the_l2_entry;
}

static uint64_t
qcow2_get_file_ofst_from_virtual_addr(struct qcow2_s *s, uint64_t vaddr,
				      bool alloc_if_not_existing) {
  uint64_t l1_index, l2_index, l2_entry_num;
  uint64_t the_l1_entry,the_l2_entry;
  uint64_t l2_table_off;
  uint64_t cluster_offset;

  uint64_t refblock_entries, refblock_index,
	   reft_index;
  uint64_t the_reft_entry;
  uint64_t refblock_off;
  uint16_t the_refblock_entry;

  assert(vaddr % s->cluster_size == 0);
  assert(alloc_if_not_existing == false);

  l2_entry_num = s->cluster_size / L2E_SIZE_NORMAL;
  l1_index = (vaddr / s->cluster_size) / l2_entry_num;

//  if (be32_to_cpu(hb->qcow2_hdr->l1_size) < (l1_index + 1) * L1E_SIZE)
//    hb->qcow2_hdr->l1_size = cpu_to_be32((l1_index + 1) * L1E_SIZE);

  the_l1_entry = be64_to_cpu(s->l1_table[l1_index]);

  l2_table_off = the_l1_entry & L1E_OFFSET_MASK;
  if (l2_table_off == 0) {
      if (alloc_if_not_existing) {
//      l2_table_off = hyperdisk_incremental_qcow2_alloc_a_cluster(hb);
//      assert((l2_table_off & L1E_OFFSET_MASK) == l2_table_off);
//      hb->l1_table[l1_index] = cpu_to_be64(l2_table_off | QCOW_OFLAG_COPIED);
	  assert(0);
      } else {
	  return 0;
      }
  }


  l2_index = (vaddr / s->cluster_size) % l2_entry_num;
  the_l2_entry = be64_to_cpu(qcow2_get_l2_entry(s, l2_table_off, l2_index));
  if (the_l2_entry & QCOW_OFLAG_COMPRESSED) {
      assert(0);
  } else if (the_l2_entry & QCOW_OFLAG_ZERO) {
      return 0;
  } else if (!(the_l2_entry & L2E_OFFSET_MASK)) {
      return 0;
  } else {
      return the_l2_entry & L2E_OFFSET_MASK;
  }
//  assert(L2E_SIZE_NORMAL ==
//	 pread(hb->incremental_qcow2_fd, &the_l2_entry,
//	       L2E_SIZE_NORMAL,
//	       l2_table_off + l2_index * L2E_SIZE_NORMAL));
//  the_l2_entry = cpu_to_be64(cluster_offset | QCOW_OFLAG_COPIED);
//  assert(L2E_SIZE_NORMAL ==
//	 pwrite(hb->incremental_qcow2_fd, &the_l2_entry,
//		L2E_SIZE_NORMAL,
//		l2_table_off + l2_index * L2E_SIZE_NORMAL));
//#if 0
//  printf("0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64"\n", guest_offset,
//	 hb->page_size,cluster_offset);
//#endif
}

static struct qcow2_s *
qcow2_open(const char *path) {
    struct qcow2_s *s = malloc(sizeof(struct qcow2_s));

    s->fd = open(path, O_RDWR);
    assert(0 <= s->fd);

    s->file_size = lseek(s->fd, 0, SEEK_END);

    assert(sizeof(struct QCowHeader) ==
	   pread(s->fd, &(s->hdr), sizeof(struct QCowHeader), 0));

    s->hdr.magic = be32_to_cpu(s->hdr.magic);
    s->hdr.version = be32_to_cpu(s->hdr.version);
    s->hdr.backing_file_offset = be64_to_cpu(s->hdr.backing_file_offset);
    s->hdr.backing_file_size = be32_to_cpu(s->hdr.backing_file_size);
    s->hdr.size = be64_to_cpu(s->hdr.size);
    s->hdr.cluster_bits = be32_to_cpu(s->hdr.cluster_bits);
    s->hdr.crypt_method = be32_to_cpu(s->hdr.crypt_method);
    s->hdr.l1_table_offset = be64_to_cpu(s->hdr.l1_table_offset);
    s->hdr.l1_size = be32_to_cpu(s->hdr.l1_size);
    s->hdr.refcount_table_offset = be64_to_cpu(s->hdr.refcount_table_offset);
    s->hdr.refcount_table_clusters =
      be32_to_cpu(s->hdr.refcount_table_clusters);
    s->hdr.snapshots_offset = be64_to_cpu(s->hdr.snapshots_offset);
    s->hdr.nb_snapshots = be32_to_cpu(s->hdr.nb_snapshots);
    s->hdr.incompatible_features    = 0;
    s->hdr.compatible_features      = 0;
    s->hdr.autoclear_features       = 0;
    s->hdr.refcount_order           = 4;
    s->hdr.header_length            = 72;

    assert(s->hdr.magic == QCOW_MAGIC);
    assert(s->hdr.version == 2);
    assert(MIN_CLUSTER_BITS <= s->hdr.cluster_bits &&
	   s->hdr.cluster_bits <= MAX_CLUSTER_BITS);
    assert(s->hdr.backing_file_offset == 0);
    assert(s->hdr.crypt_method == 0);
    assert(s->hdr.nb_snapshots == 0);

    s->cluster_size = 1 << s->hdr.cluster_bits;
    assert(s->file_size % s->cluster_size == 0);

    //s->refcount_order = s->hdr.refcount_order;
    //s->refcount_bits = 1 << s->refcount_order;
    //s->refcount_max = UINT64_C(1) << (s->refcount_bits - 1);
    //s->refcount_max += s->refcount_max - 1;

    s->l1_table = malloc(sizeof(uint64_t) * s->hdr.l1_size);
    assert(sizeof(uint64_t) * s->hdr.l1_size ==
	   pread(s->fd, s->l1_table,
		 sizeof(uint64_t) * s->hdr.l1_size,
		 s->hdr.l1_table_offset));

    s->reftable = malloc(s->cluster_size * s->hdr.refcount_table_clusters);
    assert(s->cluster_size * s->hdr.refcount_table_clusters ==
	   pread(s->fd, s->reftable,
		 s->cluster_size * s->hdr.refcount_table_clusters,
		 s->hdr.refcount_table_offset));



    return s;
}

static void
qcow2_close(struct qcow2_s *s) {
    close(s->fd);
    free(s);
}


int main(int argc, char *argv[]) {
    assert(argc == 2);

    struct qcow2_s *s = qcow2_open(argv[1]);

    char *out_file = strcat(argv[1], ".raw");
    int fd = open(out_file, O_RDWR | O_CREAT);
    assert(0 <= fd);
    assert(0 == ftruncate(fd, s->hdr.size));
    char *out_mmapped = mmap(NULL, s->hdr.size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, 0);

    for (uint64_t i = 0; i < s->hdr.size; i += s->cluster_size) {
	uint64_t qcow2_file_ofst =
	  qcow2_get_file_ofst_from_virtual_addr(s, i, false);
	if (qcow2_file_ofst != 0)
	  assert(s->cluster_size ==
		 pread(s->fd, out_mmapped + i, s->cluster_size, qcow2_file_ofst));
    }
    close(fd);
    qcow2_close(s);
    return 0;
}
