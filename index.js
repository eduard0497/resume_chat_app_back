require("dotenv").config();
const express = require("express");
const cors = require("cors");
const http = require("http");
const app = express();
const knex = require("knex");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// all uses
const corsOptions = process.env.IS_DEV_MODE
  ? {
      origin: ["http://localhost:3001"],
    }
  : {
      origin: [process.env.FRONT_DOMAIN],
    };

console.log(corsOptions);
app.use(cors(corsOptions));
app.use(express.json());

// server
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server, {
  cors: corsOptions,
});

// KNEX Config
const configKnex = () => {
  if (process.env.IS_DEV_MODE) {
    return {
      client: "pg",
      connection: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
      },
    };
  } else {
    return {
      client: "pg",
      connection: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        ssl: { rejectUnauthorized: false },
      },
    };
  }
};
const db = knex(configKnex());

// Constant Messages
const _SERVER_SIDE_ERROR_MESSAGE = "Server side error";

// Table Names
const _DB_TABLE_USERS = "users";
const _DB_TABLE_CONVERSATIONS = "conversations";
const _DB_TABLE_MESSAGES = "messages";
const _DB_TABLE_FRIENDSHIPS = "friendships";
const _DB_TABLE_USER_SOCKET = "user_socket";

// Friendship statuses
const _FRIENDSHIP_STATUS_PENDING = "pending";
const _FRIENDSHIP_STATUS_ACCEPTED = "accepted";

// Middlewares
const verifyToken = (req, res, next) => {
  try {
    const { token } = req.body;
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.body.decoded_user_id = decodedToken.user_id;
    next();
  } catch (e) {
    sendError(res, "Not authorized");
  }
};

// Endpoints

app.get("/", (req, res) => {
  res.json("TESTING...");
});

app.post("/register-user", (req, res) => {
  const { username, password, first_name, last_name } = req.body;

  db(_DB_TABLE_USERS)
    .select("*")
    .where({
      username,
    })
    .then((data) => {
      if (!data.length) {
        let hash = bcrypt.hashSync(password, 10);
        db(_DB_TABLE_USERS)
          .returning("*")
          .insert({
            username,
            password: hash,
            first_name,
            last_name,
            account_created: new Date(),
          })
          .then((data) => {
            if (!data.length) {
              sendError(res, "Inserted inputs returned null");
            } else {
              sendConfirmMessage(res, "User has been registered successfully");
            }
          })
          .catch((e) => {
            sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
          });
      } else {
        sendError(res, "The username already exists");
      }
    })
    .catch((e) => {
      console.log(e);
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/user-login", (req, res) => {
  const { username, password } = req.body;

  db(_DB_TABLE_USERS)
    .select("*")
    .where({
      username,
    })
    .then((data) => {
      if (!data.length) {
        sendError(res, "No such username");
      } else if (data.length > 1) {
        sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
      } else {
        let db_stored_password = data[0].password;
        if (!bcrypt.compareSync(password, db_stored_password)) {
          sendError(res, "Wrong password");
        } else {
          const token = jwt.sign(
            { user_id: data[0].id },
            process.env.JWT_SECRET_KEY
          );
          sendConfirmData(res, token);
        }
      }
    })
    .catch((e) => {
      console.log(e);
    });
});

app.post("/check-token", verifyToken, (req, res) => {
  sendConfirmMessage(res, "Valid Token");
});

app.post("/authorize-user-to-proceed", verifyToken, (req, res) => {
  sendConfirmMessage(res, "User authorized");
});

app.post("/get-user-info", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;
  db(_DB_TABLE_USERS)
    .select("*")
    .where({
      id: decoded_user_id,
    })
    .then((data) => {
      if (!data.length) {
        sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
      } else if (data.length == 1) {
        sendConfirmData(res, data);
      } else {
        sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
      }
    });
});

app.post("/update-user-info", verifyToken, (req, res) => {
  const { decoded_user_id, first_name, last_name } = req.body;

  db(_DB_TABLE_USERS)
    .returning("*")
    .update({
      first_name,
      last_name,
    })
    .where({
      id: decoded_user_id,
    })
    .then((data) => {
      if (!data.length) {
        sendError(res, "Unable to update the user info");
      } else {
        db(_DB_TABLE_USERS)
          .select("*")
          .where({
            id: decoded_user_id,
          })
          .then((data) => {
            sendConfirmData(res, data);
          });
      }
    })
    .catch((e) => {
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/search-user", verifyToken, (req, res) => {
  const { decoded_user_id, username } = req.body;

  db(_DB_TABLE_USERS)
    .select(
      `${_DB_TABLE_USERS}.id as user_id`,
      `${_DB_TABLE_USERS}.username`,
      `${_DB_TABLE_USERS}.first_name`,
      `${_DB_TABLE_USERS}.last_name`,
      `${_DB_TABLE_USERS}.account_created`,
      `${_DB_TABLE_FRIENDSHIPS}.id as friendship_id`,
      `${_DB_TABLE_FRIENDSHIPS}.requestor as friendship_requestor`,
      `${_DB_TABLE_FRIENDSHIPS}.recipient as friendship_recipient`,
      `${_DB_TABLE_FRIENDSHIPS}.status`
    )
    .leftJoin(_DB_TABLE_FRIENDSHIPS, function () {
      this.on(
        `${_DB_TABLE_FRIENDSHIPS}.requestor`,
        "=",
        `${_DB_TABLE_USERS}.id`
      )
        .andOn(`${_DB_TABLE_FRIENDSHIPS}.recipient`, "=", decoded_user_id)
        .orOn(function () {
          this.on(
            `${_DB_TABLE_FRIENDSHIPS}.recipient`,
            "=",
            `${_DB_TABLE_USERS}.id`
          ).andOn(`${_DB_TABLE_FRIENDSHIPS}.requestor`, "=", decoded_user_id);
        });
    })
    .where({
      username,
    })
    .andWhereNot({
      [_DB_TABLE_USERS + ".id"]: decoded_user_id,
    })
    .then((data) => {
      let newArray = data.map((obj) => {
        let newObj = { ...obj };
        delete newObj["password"];
        return newObj;
      });
      sendConfirmData(res, newArray);
    })
    .catch((e) => {
      console.log(e);
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/send-friend-request", verifyToken, (req, res) => {
  const { decoded_user_id, personID } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .returning([
      "id as friendship_id",
      "requestor as friendship_requestor",
      "recipient as friendship_recipient",
      "status",
    ])
    .insert({
      requestor: decoded_user_id,
      recipient: personID,
      status: _FRIENDSHIP_STATUS_PENDING,
    })
    .then(async (data) => {
      if (!data.length) {
        sendError(res, "Unable to send the request");
      } else {
        let { friendship_recipient } = data[0];
        let socket_to_emit_to = await retrieveSocketID(friendship_recipient);
        io.to(socket_to_emit_to).emit(
          "new_friend_request",
          "You have a new friend request"
        );
        sendConfirmData(res, data);
      }
    })
    .catch((e) => {
      console.log(e);
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/get-my-friend-requests", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .select(
      `${_DB_TABLE_FRIENDSHIPS}.id as request_id`,
      `${_DB_TABLE_USERS}.first_name`,
      `${_DB_TABLE_USERS}.last_name`,
      `${_DB_TABLE_USERS}.username`,
      `${_DB_TABLE_USERS}.account_created`
    )
    .leftJoin(_DB_TABLE_USERS, function () {
      this.on(
        `${_DB_TABLE_USERS}.id`,
        "=",
        `${_DB_TABLE_FRIENDSHIPS}.recipient`
      );
    })
    .where({
      [`${_DB_TABLE_FRIENDSHIPS}.status`]: _FRIENDSHIP_STATUS_PENDING,
      [`${_DB_TABLE_FRIENDSHIPS}.requestor`]: decoded_user_id,
    })
    .then((data) => {
      sendConfirmData(res, data);
    })
    .catch((e) => {
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/get-pending-approval-friend-requests", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .select(
      `${_DB_TABLE_FRIENDSHIPS}.id as request_id`,
      `${_DB_TABLE_USERS}.first_name`,
      `${_DB_TABLE_USERS}.last_name`,
      `${_DB_TABLE_USERS}.username`,
      `${_DB_TABLE_USERS}.account_created`
    )
    .leftJoin(_DB_TABLE_USERS, function () {
      this.on(
        `${_DB_TABLE_USERS}.id`,
        "=",
        `${_DB_TABLE_FRIENDSHIPS}.requestor`
      );
    })
    .where({
      [`${_DB_TABLE_FRIENDSHIPS}.status`]: _FRIENDSHIP_STATUS_PENDING,
      [`${_DB_TABLE_FRIENDSHIPS}.recipient`]: decoded_user_id,
    })
    .then((data) => {
      sendConfirmData(res, data);
    })
    .catch((e) => {
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/accept-friend-request", verifyToken, (req, res) => {
  const { decoded_user_id, requestID } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .returning("*")
    .update({
      status: _FRIENDSHIP_STATUS_ACCEPTED,
    })
    .where({
      id: requestID,
      recipient: decoded_user_id,
    })
    .then(async (data) => {
      if (!data.length) {
        sendError(res, "Unable to accept the request");
      } else {
        let { requestor } = data[0];
        let socket_to_emit_to = await retrieveSocketID(requestor);
        io.to(socket_to_emit_to).emit(
          "friend_request_accepted",
          "Your friend request has been accepted"
        );
        sendConfirmData(res, data);
      }
    })
    .catch((e) => {
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/reject-friend-request", verifyToken, (req, res) => {
  const { decoded_user_id, requestID } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .returning("*")
    .del()
    .where({
      id: requestID,
      recipient: decoded_user_id,
    })
    .then((data) => {
      if (!data.length) {
        sendError(res, "Unable to reject the request");
      } else {
        sendConfirmData(res, data);
      }
    })
    .catch((e) => {
      console.log(e);
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/load-current-friends", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .select(
      `${_DB_TABLE_FRIENDSHIPS}.id as friendship_id`,
      `${_DB_TABLE_USERS}.id as user_id`,
      `${_DB_TABLE_USERS}.username`,
      `${_DB_TABLE_USERS}.first_name`,
      `${_DB_TABLE_USERS}.last_name`,
      `${_DB_TABLE_USERS}.account_created`
    )
    .leftJoin(_DB_TABLE_USERS, function () {
      this.on(
        `${_DB_TABLE_FRIENDSHIPS}.requestor`,
        "=",
        `${_DB_TABLE_USERS}.id`
      ).orOn(
        `${_DB_TABLE_FRIENDSHIPS}.recipient`,
        "=",
        `${_DB_TABLE_USERS}.id`
      );
    })
    .where(function () {
      this.where({
        requestor: decoded_user_id,
        status: _FRIENDSHIP_STATUS_ACCEPTED,
      }).orWhere({
        recipient: decoded_user_id,
        status: _FRIENDSHIP_STATUS_ACCEPTED,
      });
    })
    .andWhere(function () {
      this.whereNot({
        [`${_DB_TABLE_USERS}.id`]: decoded_user_id,
      });
    })
    .then((data) => {
      sendConfirmData(res, data);
    })
    .catch((e) => {
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/unfriend", verifyToken, (req, res) => {
  const { friendship_id } = req.body;

  db(_DB_TABLE_FRIENDSHIPS)
    .returning("*")
    .del()
    .where({
      id: friendship_id,
    })
    .then((data) => {
      if (!data.length) {
        sendError(res, "Unable to Remove a friend");
      } else {
        sendConfirmMessage(res, "Friend was removed successfully");
      }
    })
    .catch((e) => {
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/start-messaging-from-friends-list", verifyToken, (req, res) => {
  const { decoded_user_id, personID } = req.body;

  db(_DB_TABLE_CONVERSATIONS)
    .select("*")
    .where({
      user1_id: decoded_user_id,
      user2_id: personID,
    })
    .orWhere({
      user1_id: personID,
      user2_id: decoded_user_id,
    })
    .then((data) => {
      if (!data.length) {
        db(_DB_TABLE_CONVERSATIONS)
          .returning("*")
          .insert({
            user1_id: decoded_user_id,
            user2_id: personID,
            created_at: new Date(),
          })
          .then((data) => {
            sendConfirmData(res, data);
          });
      } else {
        sendConfirmData(res, data);
      }
    })
    .catch((e) => {
      console.log(e);
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/get-current-user-conversations", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;

  db(_DB_TABLE_CONVERSATIONS)
    .select(
      `${_DB_TABLE_CONVERSATIONS}.id as conversation_id`,
      `${_DB_TABLE_USERS}.id as user_id`,
      `${_DB_TABLE_USERS}.username`,
      `${_DB_TABLE_USERS}.first_name`,
      `${_DB_TABLE_USERS}.last_name`
    )
    .join(_DB_TABLE_USERS, function () {
      this.on(
        `${_DB_TABLE_CONVERSATIONS}.user1_id`,
        "=",
        `${_DB_TABLE_USERS}.id`
      ).orOn(
        `${_DB_TABLE_CONVERSATIONS}.user2_id`,
        "=",
        `${_DB_TABLE_USERS}.id`
      );
    })
    .leftJoin(_DB_TABLE_MESSAGES, function () {
      this.on(function () {
        this.on(
          `${_DB_TABLE_MESSAGES}.conversation_id`,
          "=",
          `${_DB_TABLE_CONVERSATIONS}.id`
        );
      }).andOn(
        `${_DB_TABLE_MESSAGES}.sent_at`,
        "=",
        db.raw(
          `(SELECT MAX(sent_at) FROM ${_DB_TABLE_MESSAGES} WHERE conversation_id = ${_DB_TABLE_CONVERSATIONS}.id)`
        )
      );
    })
    .where(function () {
      this.where({
        user1_id: decoded_user_id,
      }).orWhere({
        user2_id: decoded_user_id,
      });
    })
    .andWhere(function () {
      this.whereNot({
        [`${_DB_TABLE_USERS}.id`]: decoded_user_id,
      });
    })
    .orderBy(`${_DB_TABLE_MESSAGES}.sent_at`, "desc")
    .then((data) => {
      sendConfirmData(res, data);
    })
    .catch((e) => {
      console.log(e);
      sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
    });
});

app.post("/get-conversation-messages", verifyToken, async (req, res) => {
  const { decoded_user_id, conversationID } = req.body;

  try {
    let data = await retrieveMessagesAndOtherPartyID(
      conversationID,
      decoded_user_id
    );
    if (!data.otherPartyID) {
      sendError(res, "Unable to get other party ID");
    } else {
      res.json({
        status: 1,
        myID: decoded_user_id,
        otherPartyID: data.otherPartyID,
        messages: data.messages,
      });
    }
  } catch (error) {
    console.log(error);
    sendError(res, _SERVER_SIDE_ERROR_MESSAGE);
  }
});

io.on("connection", (socket) => {
  //
  startConnection(socket);
  //

  //
  socket.on(
    "send_message",
    async ({ senderID, otherPartyID, conversationID, message }, callback) => {
      db(_DB_TABLE_MESSAGES)
        .returning("*")
        .insert({
          conversation_id: conversationID,
          sender_id: senderID,
          message_content: message,
          sent_at: new Date(),
          is_read: false,
        })
        .then(async (data) => {
          if (!data.length) {
            callback({
              status: 0,
              msg: "Error occured while saving the message",
            });
            console.log("ERROR OCCURED");
          } else {
            let socketID = await retrieveSocketID(otherPartyID);
            io.to(socketID).emit("receive_message", data[0]);
            callback({
              status: 1,
              msg: "Message saved",
            });
          }
        });
    }
  );
  //

  // disconnect socket function
  socket.on("disconnect", () => {
    console.log(socket.id + " disconnected");
  });
});

// LISTENING
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Listening to port: ${PORT}`);
});

//Side Functions
const sendError = (res, msg) => {
  res.json({
    status: 0,
    msg,
  });
};

const sendConfirmMessage = (res, msg) => {
  res.json({
    status: 1,
    msg,
  });
};

const sendConfirmData = (res, ...data) => {
  res.json({
    status: 1,
    data: data.length === 1 ? data[0] : data,
  });
};

// Socket Side Functions

const startConnection = (socket) => {
  const { token } = socket.handshake.query;
  const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
  const connectingUserID = decodedToken.user_id;

  db(_DB_TABLE_USER_SOCKET)
    .select("*")
    .where({
      user_id: connectingUserID,
    })
    .then((data) => {
      if (!data.length) {
        db(_DB_TABLE_USER_SOCKET)
          .returning("*")
          .insert({
            user_id: connectingUserID,
            socket_id: socket.id,
          })
          .then((data) => {
            if (!data.length) {
              console.log("Unable to add new Socket ID");
              socket.emit("error", "Unable to add new Socket ID");
            } else {
              console.log(connectingUserID + " | " + socket.id + " | +");
              socket.emit("connection_established", "Connection Established");
            }
          })
          .catch((e) => {
            console.log(
              "Socket connection Error insertting socket into database"
            );
            console.log(e);
            socket.emit("error", _SERVER_SIDE_ERROR_MESSAGE);
          });
      } else {
        db(_DB_TABLE_USER_SOCKET)
          .returning("*")
          .update({
            socket_id: socket.id,
          })
          .where({
            user_id: connectingUserID,
          })
          .then((data) => {
            if (!data.length) {
              console.log("Unable to update user socket ID");
              socket.emit("error", "Unable to update user socket ID");
            } else {
              console.log(connectingUserID + " | " + socket.id + " | +");
              socket.emit("connection_established", "Connection Established");
            }
          })
          .catch((e) => {
            console.log("Unable to Update and Return the socket ID");
            console.log(e);
            socket.emit("error", _SERVER_SIDE_ERROR_MESSAGE);
          });
      }
    })
    .catch((e) => {
      console.log("Socket connection outter ERROR");
      socket.emit("error", _SERVER_SIDE_ERROR_MESSAGE);
    });

  //
  // storeOrUpdateSocketID(connectingUserID, socket.id)
  //   .then((result) => {
  //     console.log(connectingUserID + " | " + socket.id + " | +");
  //     socket.emit("connection_established", "Connection Established");
  //   })
  //   .catch((error) => {
  //     console.log(error);
  //     socket.emit("error", "Unable to update Socket ID");
  //   });
};

const retrieveMessagesAndOtherPartyID = async (conversationID, requestorID) => {
  try {
    let messages = await db(_DB_TABLE_MESSAGES)
      .select("*")
      .where({
        conversation_id: conversationID,
      })
      .orderBy("sent_at", "asc");

    let conversationData = await db(_DB_TABLE_CONVERSATIONS)
      .select("user1_id", "user2_id")
      .where({
        id: conversationID,
      });

    let otherPartyID = null;
    if (conversationData.length > 0) {
      if (conversationData[0].user1_id === requestorID) {
        otherPartyID = conversationData[0].user2_id;
      } else if (conversationData[0].user2_id === requestorID) {
        otherPartyID = conversationData[0].user1_id;
      }
    }

    return { otherPartyID, messages };
  } catch (error) {
    console.error("Error:", error);
    throw error;
  }
};

const retrieveSocketID = async (userID) => {
  let socketID = null;
  await db(_DB_TABLE_USER_SOCKET)
    .select("socket_id")
    .where({
      user_id: userID,
    })
    .then((data) => {
      socketID = data[0].socket_id;
    });
  return socketID;
};
