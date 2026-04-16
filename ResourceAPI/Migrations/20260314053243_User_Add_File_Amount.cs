using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ResourceAPI.Migrations
{
    /// <inheritdoc />
    public partial class User_Add_File_Amount : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<decimal>(
                name: "Amount",
                table: "User",
                type: "decimal(18,2)",
                nullable: false,
                defaultValue: 0m);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Amount",
                table: "User");
        }
    }
}
