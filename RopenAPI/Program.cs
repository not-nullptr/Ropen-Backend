using MongoDB.Driver;

Console.Title = "Ropen Backend";

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

int count = 0;
string connection = "mongodb://localhost:27017/";
var client = new MongoClient(connection);
        // This while loop is to allow us to detect if we are connected to the MongoDB server
        // if we are then we miss the execption but after 5 seconds and the connection has not
        // been made we throw the execption.
        while (client.Cluster.Description.State.ToString() == "Disconnected") {
            Thread.Sleep(100);
            if (count++ >= 50) {throw new Exception("Ropen Backend can't continue because no MongoDB database was detected. If it is running, make sure that it is running on localhost:27017.");            }
        }

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

Console.WriteLine("[" + DateTime.Now + "] " + "Initialized!");

app.Run();
