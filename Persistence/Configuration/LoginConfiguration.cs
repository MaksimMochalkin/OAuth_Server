namespace Persistence.Configuration
{
    using Domain.Entities;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Metadata.Builders;

    internal sealed class LoginConfiguration : IEntityTypeConfiguration<ClientLoginInfo>
    {
        public void Configure(EntityTypeBuilder<ClientLoginInfo> builder)
        {
            builder.ToTable(nameof(ClientLoginInfo));
            
            builder.HasKey(login => login.Id);
            builder.Property(login => login.PasswordHash).IsRequired();
            builder.Property(login => login.PasswordSalt).IsRequired();
            builder.Property(login => login.PhoneNumber).IsRequired();
            builder.Property(login => login.RefreshToken).IsRequired();
            builder.Property(login => login.RefreshTokenExpiryTime).IsRequired();
        }
    }
}
