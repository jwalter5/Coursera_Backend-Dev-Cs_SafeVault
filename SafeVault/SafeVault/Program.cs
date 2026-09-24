using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// create and open In-Memory-Database
var databaseConnection = new SqliteConnection("Data Source=:memory:");
databaseConnection.Open();

using (var command = databaseConnection.CreateCommand())
{
    command.CommandText =
        """
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            Email TEXT NOT NULL
        );
        """;

    command.ExecuteNonQuery();
}

builder.Services.AddSingleton(databaseConnection);

var app = builder.Build();

var defaultFileOptions = new DefaultFilesOptions();
defaultFileOptions.DefaultFileNames.Clear();
defaultFileOptions.DefaultFileNames.Add("webform.html");

app.UseDefaultFiles(defaultFileOptions);
app.UseStaticFiles();
app.MapControllers();

// Cleanly close database connection
app.Lifetime.ApplicationStopping.Register(databaseConnection.Dispose);

app.Run();
