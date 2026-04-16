using Microsoft.EntityFrameworkCore;

namespace ResourceAPI
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext()
        {
        }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {

        }
        public virtual DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.ToTable("User");

                entity.Property(e => e.Password).HasMaxLength(255);
                entity.Property(e => e.UserName).HasMaxLength(255);
            });

            base.OnModelCreating(modelBuilder);

            // Customize your identity models here, if needed.

        }
    }
}

