const db = require('mysql')
var https = require('https');
const fs = require('fs')
const express = require('express')
var request = require('request')
require('dotenv').config({ debug: true })
const jwt = require('jsonwebtoken')
const EmailParams = require("mailersend").EmailParams;
const MailerSend = require("mailersend");
const Recipient = require("mailersend").Recipient;
// const Flutterwave = require('flutterwave-node-v3');
const _ = require('underscore')
const cors = require('cors')
const messagebird = require('messagebird')('wa3a4eMjiVleCXCI0a63rJZL6')
const sdk = require('api')('@onesignal/v9.0#cx17o913l504mfxw');
// App keys and id are different from the blipmoore customer app keys and id
const oneSignalAppKey = 'Y2JhZWQwZTAtNjNmYy00MjhjLWE2NzMtNTdkMDgwMzcwNjhl'
const oneSignalAppId = 'eeeff331-2d19-4e4d-9f14-31ca96237bd3'
const blipmoore_oneSignalAppId='05491084-3b03-43ed-9ad9-d56d6906f653'
const blipmoore_oneSignalAppKey='YTQxZDNhNzYtYTI4Yy00NWY5LTlmMDMtZDkxODU4NDUxZjdj'
const { Server } = require('socket.io')
const port = process.env.PORT || 19002;
const app = express()
const { Expo } = require('expo-server-sdk')
const bcrypt = require('bcrypt')
const path = require('path')
const AllKeys = {
    ipAddress: process.env.URL || 'http://192.168.100.12:19002'
}
const StreamChat = require('stream-chat').StreamChat
var paystack = require('paystack')(`${process.env.PAYSTACK_LIVE_SECRET_KEY}`);
// const accountSid = process.env.AC15cc42fe249311ea4f608d751af1da1c;
// const authToken = process.env['8e495f2be962036180aa81d3681dfae7'];
// const client = require('twilio')(accountSid, authToken);
var sendNotification = function(data,app_name) {
    var headers
    if (app_name === 'blipmoore') {
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": `Basic ${blipmoore_oneSignalAppKey}`
        };   
    }else{
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": `Basic ${oneSignalAppKey}`
        };
    }
    var options = {
      host: "onesignal.com",
      port: 443,
      path: "/api/v1/notifications",
      method: "POST",
      headers: headers
    };
    
    var req = https.request(options, function(res) {
      res.on('data', function(data) {
        console.log("Response:");
        console.log(JSON.parse(data));
      });
    });
    
    req.on('error', function(e) {
      console.log("ERROR:");
      console.log(e);
    });
    
    req.write(JSON.stringify(data));
    req.end();
  };
// Define values for stream chat api.
const api_key = '449vt742ex2f'
const api_secret = 'fvfzknctjcq3nqaacugy4e74ue669axk6dthuph8hmanw8adt9jm7ukngr7tbnan'

// Initialize a Server Client
const serverClient = StreamChat.getInstance(api_key, api_secret,'1196435');
// const apn_template = `{
//     "aps": {
//         "content-available": 1
//     }
//   }`;
  
//   const pushProviderConfig = {
//     name: 'blipmoore_firebase',
//     type: 'firebase',
//     firebase_apn_template: apn_template
//   };
  
//   serverClient.upsertPushProvider(pushProviderConfig);

app.use(cors())
let expo = new Expo({ accessToken: process.env.EXPO_ACCESS_TOKEN });

// client.verify.services.create({friendlyName: 'REIN'})
// .then(service => console.log(service.sid));
var params = {
    originator: 'blipmoore',
    type: 'sms'
};

const listeningServer = app.listen(port,  () => console.log(`Listening on port ${port}`))

const io = new Server(listeningServer, {
    cors: {
        origin:`${AllKeys.ipAddress}`,
        methods:['GET','POST']
    }
})

io.on("connection", (socket) => {
    socket.on('join_room', (data) => {
        socket.join(data)
        console.log(`User with ID: ${socket.id} joined room: ${data}`)
    })
    socket.on('send_message', (data) => {
        socket.to(data.room).emit('receive_message', data)
    })
    socket.on("disconnect", () => {
        console.log('User disconnected')
    })
})
app.get('/', (req, res) => {   res.status(200).send({     message: "Hello!",   }); });

var conn = db.createConnection({
    host:'localhost',
    user:'root',
    password:'',
    database:'users'
})

// var conn = db.createPool({
//     host:'us-cdbr-east-06.cleardb.net',
//     user:'b1e1f2588cd38a',
//     password:'f902ebbe',
//     database:'heroku_0213e165e455431'
// })
// const handleDisconnect = () => {
//     conn = db.createConnection({
//         host:'us-cdbr-east-06.cleardb.net',
//         user:'b1e1f2588cd38a',
//         password:'f902ebbe',
//         database:'heroku_0213e165e455431'
//     })
// }
// conn.connect(function(err){
//     if (err) console.log('Errors', err)
//     console.log('connenected');
// })
// conn.on('error', (err) => {
//     console.log(err)
//     if(err.code === 'PROTOCOL_CONNECTION_LOST') { // Connection to the MySQL server is usually
//         handleDisconnect();                         // lost due to either server restart, or a
//     }
// })
app.get('/checkVersion', (req,res) => {
    var sql = "SELECT * FROM app_version"
    conn.query(sql, (err, result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            console.log(result)
            if (result[0].version == req.query.version) {
                res.send({ success:true })
            }else{
                res.send({ success:false })
            }
        }
    })
})

app.get('/createMailerLiteSubWeb', (req, res) => {
    var options = {
        "method": "GET",
        "url": `${process.env.MAILER_LITE_URL}/api/groups`,
        "headers": {
        "Authorization": `Bearer ${process.env.MAILER_LITE_API_TOKEN}`,
         "Content-Type": "application/json",
         "Accept": "application/json"
        },
        "body": {
         "filter": `tips and tricks on cleaning home`,
         "limit": `2`,
       },
       json:true
    };
    request(options, function (error, response, body) {
        if (error) {
            console.log(error)
            res.send({ success:false })
            return
        };
        options = {
            "method": "POST",
            "url": `${process.env.MAILER_LITE_URL}/api/subscribers`,
            "headers": {
            "Authorization": `Bearer ${process.env.MAILER_LITE_API_TOKEN}`,
             "Content-Type": "application/json",
             "Accept": "application/json"
            },
            "body": {
             "email": `${req.query.email}`,
             'groups': [body.data[0].id]
           },
           json:true
        };
        request(options, function (error, response, body) {
            if (error) {
                console.log(error)
                res.send({ success:false })
                return
            };
            res.send({ success:true })
        })
    })
})

app.get('/insertIntoUserChat', (req,res) => {
    var sql = "SELECT id FROM userchats WHERE userid=? AND agent_id=?";
    conn.query(sql,[req.query.userid,req.query.agentId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
        } else {
            if (result.length < 1) {
                sql = "INSERT INTO userchats (agent_id,agent_name,userid,last_message,time_of_message,customer_name) VALUES(?,?,?,?,?,?)";
                conn.query(sql,[req.query.agentId,req.query.agentName,req.query.userid,req.query.lastMessage,req.query.time,req.query.customerName],(err,result) => {
                    if (err) {
                        console.log(err)
                    }else{
                        sql = "INSERT INTO chats (user_chatid,chat,time_of_message,authorId) VALUES(?,?,?,?)";
                        conn.query(sql,[result.insertId,req.query.lastMessage,req.query.time,req.query.authorId],(err,result) => {
                            if (err) {
                                console.log(err)
                            }
                        })
                    }
                });
            }else{
                sql = "UPDATE userchats SET last_message=?, time_of_message=? WHERE agent_id=? AND userid=?";
                conn.query(sql,[req.query.lastMessage,req.query.time,req.query.agentId,req.query.userid],(err,results) => {
                    if (err) {
                        console.log(err)
                    }else{
                        sql = "INSERT INTO chats (user_chatid,chat,time_of_message,authorId) VALUES(?,?,?,?)";
                        conn.query(sql,[result[0].id,req.query.lastMessage,req.query.time,req.query.authorId],(err,result) => {
                            if (err) {
                                console.log(err)
                            }
                        })
                    }
                });
            }
            res.send({ success:true });
        }
    });
});

// Create User Token
app.get('/getUserToken', (req,res) => {
    console.log(req.query.userid)
    const token = serverClient.createToken(req.query.userid);
    res.send({ token })
})

// Get All Grouped Chats
app.get('/getAllChats', (req,res) => {
    var sql = "SELECT * FROM userchats WHERE userid=? OR agent_id =? ORDER BY time_of_message DESC";
    conn.query(sql,[req.query.id,req.query.agentId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err)
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result }); // <---   
            }else{
                res.send({ success:false }); // <---
            }
        }
    });
});

// Get All Individual Chats
app.get('/fetchRoomChats', (req,res) => {
    var sql = "SELECT * FROM chats WHERE user_chatid=? ORDER BY time_of_message DESC";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err)
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result }); // <---   
            }else{
                res.send({ success:false }); // <---
            }
        }
    });
});
    
app.get('/queryUser', (req,res) => {
    var sql = "SELECT number,email FROM usersinfo WHERE number=? OR email =?";
    conn.query(sql,[req.query.number,req.query.email], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
        } else {
            res.send({ success:true,result });
        }
    });
});

app.get('/sendOtp', (req,res) => {
    messagebird.verify.create(`${req.query.number}`, params, function (err, response) {
        if (err) {
          return console.log(err);
        }
        res.send({ response })
        console.log(response);
    });
});

app.get('/verifyOtp', (req,res) => {
    messagebird.verify.verify(req.query.id, req.query.token, function (err, response) {
        if (err) {
        res.send({ success:false,response:err })
          return console.log(err);
        }
        res.send({ success:true, response })
        console.log(response);
      });
});


// Check if user has an order
app.get('/getCleanerThatAccepted', (req,res) => {
    var sql = "SELECT * FROM usersinfo WHERE id=?";
    conn.query(sql,[req.query.cleanerid], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err, 'there was an error getting cleaner')
        } else {
            if (result.length > 0) {
                res.send({ success:true,response: result[0] });   
            }else{
                res.send({ success:false });
            }
        }
    });
});

// forgotten password
app.get('/resetPwd', (req,res) => {
    const JWT_SECRET = process.env.JWT_SECRET
    const { email } = req.query
    var sql = "SELECT * FROM usersinfo WHERE email=?"
    conn.query(sql, [email], (err, result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            res.send({ success:true })
            if (result.length > 0) {
                const secret = result[0].password + JWT_SECRET
                var payload = {
                    id:result[0].id,
                    email:result[0].email
                }
                const token = jwt.sign(payload,secret, {expiresIn:'15m'})
                const mailersend = new MailerSend({
                    api_key: process.env.MAILER_SEND_API_KEY,
                });
                const recipients = [new Recipient(`${email}`, "Recipient")];
                const personalization = [
                    {
                      email: `${email}`,
                      data: {
                        name: `${result[0].firstname}`,
                        account_name: 'blipmoore',
                        id:`${result[0].id}`,
                        token: `${token}`,
                        support_email: 'support@blipmoore.com'
                      },
                    }
                ];
                const emailParams = new EmailParams()
                    .setFrom("no-reply@blipmoore.com")
                    .setFromName("blipmoore")
                    .setRecipients(recipients)
                    .setSubject("Reset-password")
                    .setTemplateId(process.env.MAILER_SEND_FORGOTTEN_PWD_TEMP_ID)
                    .setPersonalization(personalization);
                mailersend.send(emailParams);
            }
        }
    })
})

app.get('/verifyRestPwd', (req,res) => {
    var sql = "SELECT id,password FROM usersinfo WHERE id=?"
    conn.query(sql, [req.query.id], (err,result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            if (result.length > 0) {
                const secret = process.env.JWT_SECRET + result[0].password

                try {
                    jwt.verify(req.query.token, secret)
                    res.send({ success:true })
                } catch (error) {
                    res.send({ success:false })
                    console.log(error.message)
                }
                return
            }
            res.send({ success:false })
        }
    })
})

// Insert User into database
app.get('/SignupUser', async(req,res) => {
    const salt = await bcrypt.genSalt()
    var ref = (+new Date()).toString(36)
    const signUp = async(results,isReferred) => {
        bcrypt.hash(req.query.password, salt).then(hashedPwd => {
        var sql = "INSERT INTO usersinfo (firstname,lastname,email,number,role,latitude,longitude,banned,notification_id,password,referral_code) VALUES(?,?,?,?,?,?,?,?,?,?,?)";
            conn.query(sql,[req.query.firstname,req.query.lastname,req.query.email,req.query.number,'customer','','','false','',hashedPwd,ref], (err,result) => {
                if (err) {
                    console.log(err,'there has been an error');
                    res.send({ success:false });
                } else {
                    if (isReferred && results) {
                        sql = "INSERT INTO referral(referral_code,referrer_id,referee) VALUES(?,?,?)"
                        conn.query(sql, [req.query.referral,results[0].id,result.insertId])   
                    }
                    // Do not change the "userID:result.insertId", its there for a reason lol
                    res.send({ success:true,userID:result.insertId });
                    var options = {
                        "method": "POST",
                        "url": `${process.env.COMET_CHAT_URL}/users`,
                        "headers": {
                         "apiKey": `${process.env.COMET_REST_API_KEY}`,
                         "Content-Type": "application/json",
                         "Accept": "application/json"
                        },
                        "body": {
                         "uid": `${result.insertId}`,
                         "name": `${req.query.firstname}`,
                         "avatar": "https://f004.backblazeb2.com/file/blipmoore/app+images/logo/logo.png",
                         "role": "customer"
                       },
                        "json": true
                    };
                    request(options, function (error, response, body) {
                        if (error) throw new Error(error);
                      
                        console.log(body);
                    });
                }
            });
        })
    }
    if (req.query.referral || req.query.referral.length > 0) {
        sql = "SELECT id FROM usersinfo WHERE referral_code=? LIMIT 1"
        conn.query(sql, [req.query.referral], (err, results) => {
            if (err) {
                console.log(err)
            }else{
                if (!results.length || results.length < 1) {
                    res.send({ success:false, response:'Invalid referral code' });
                }else{
                    signUp(results,true)
                }
            }
        })
    }else{
        signUp(undefined,false)
    }
});

// Update user Address
app.get('/insertAddress', async(req,res) => {
    var sql = "INSERT INTO user_address (userid,street_number,street_name,city,estate,lga,state,country) VALUES(?,?,?,?,?,?,?,?)";
    conn.query(sql,[req.query.userid,req.query.number,req.query.streetName,req.query.city,req.query.estate,req.query.lga,req.query.state,req.query.country], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            res.send({ success:true }); // <---
        }
    });
});



// Update Notification ID
app.get('/updateNotificationId', (req,res) => {
    var sql = "UPDATE usersinfo SET notification_id=? WHERE id=?";
    conn.query(sql,[req.query.notificationId,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
        }
    });
});

// Subscribe User
app.get('/SubscribeUser', (req,res) => {
    var sql = "INSERT INTO subscriptions (cleaner_id,cleaner_name,customer_id,cleaning_interval,amount,ssa,msa,lsa,elsa,deepCleaning) VALUES(?,?,?,?,?,?,?,?,?,?)";
    conn.query(sql,[req.query.cleanerId,req.query.cleanerName,req.query.customerId,req.query.cleaningInterval,req.query.amount,req.query.ssa,req.query.msa,req.query.lsa,req.query.elsa,req.query.deepCleaning], (err,result) => {
        if (err) {
            console.log(err,'There was an error')
            res.send({ success:false });
        } else {
            res.send({ success:true }); // <---
        }
    });
});


// Insert Order into database
app.get('/InsertOrder', (req,res) => {
    var sql = "INSERT INTO orders (cleaner_id,customer_id,customer_name,amount,state,date_ordered,ssa,msa,lsa,elsa,cleaningType) VALUES(?,?,?,?,?,?,?,?,?,?,?)";
    conn.query(sql,['',req.query.customerId,req.query.customerName,req.query.amount,req.query.state,req.query.date,req.query.ssa,req.query.msa,req.query.lsa,req.query.elsa,req.query.typeOfCleaning], (err,result) => {
        if (err) {
            console.log(err,'there has been an error inserting order');
            res.send({ success:false,rows:false });
        } else {
            sql = "SELECT cleaner_id FROM cleaners WHERE invoice < ? AND availability=? AND latitude >= ? AND latitude <= ? AND longitude >= ? AND longitude <= ?";
            conn.query(sql,[1000,'true',req.query.backwardLatitude,req.query.forwardLatitude,req.query.backwardLongitude,req.query.forwardLongitude], (err,results,fields) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there has been an error fetching cleaners if');
                }else {
                    let promises = []
                    var somePushTokens = []
                    let messages = [];
                    for (let i = 0; i < results.length; i++) {
                        promises.push(
                        new Promise(resolve => {
                            sql = "SELECT notification_id FROM usersinfo WHERE id=?";
                            conn.query(sql,[results[i].cleaner_id], (err,result,fields) => {
                                if (err) {
                                    console.log(err,'there was an error getting notification id');
                                    res.send({ success:false })
                                }else{
                                    somePushTokens.push({ notificationId:result[0].notification_id,cleaner_id:results[i].cleaner_id })
                                    resolve(result[0].notification_id)
                                }
                            })   
                        })
                        )
                    }
                    Promise.all(promises).then((notificationId) => {
                        for (let pushToken of somePushTokens) {
                            // Check that all your push tokens appear to be valid Expo push tokens
                              if (!Expo.isExpoPushToken(pushToken.notificationId)) {
                                  console.error(`Push token ${pushToken.notificationId} is not a valid Expo push token`);
                              }
                              let usersAddressInWords = `NO ${req.query.addressInWords}`
                              // Construct a message (see https://docs.expo.io/push-notifications/sending-notifications/)
                                messages.push({
                                  to: pushToken.notificationId,
                                  sound: 'default',
                                  title:'Incoming Request from Blipmoore',
                                  body: `SSA:${req.query.ssa}, MSA:${req.query.msa}, LSA:${req.query.lsa}, ELSA:${req.query.elsa}`,
                                  data: { cleanerId:pushToken.cleaner_id,address:usersAddressInWords,orderId:result.insertId,customerId:req.query.customerId,customerName:req.query.customerName,number:req.query.customerNumber,amount:req.query.amount,ssa:req.query.ssa,msa:req.query.msa,lsa:req.query.lsa,elsa:req.query.elsa,cleaningType:req.query.typeOfCleaning },
                                  channelId:'order2',
                                  categoryId: 'categoryId'
                                })
                        }
                              // The Expo push notification service accepts batches of notifications so
                              // that you don't need to send 1000 requests to send 1000 notifications. We
                              // recommend you batch your notifications to reduce the number of requests
                              // and to compress them (notifications with similar content will get
                              // compressed).
                          let chunks = expo.chunkPushNotifications(messages);
                          let tickets = [];
                          (async () => {
                          // Send the chunks to the Expo push notification service. There are
                          // different strategies you could use. A simple one is to send one chunk at a
                          // time, which nicely spreads the load out over time:
                          for (let chunk of chunks) {
                              try {
                              let ticketChunk = await expo.sendPushNotificationsAsync(chunk);
                              console.log(ticketChunk);
                              tickets.push(...ticketChunk);
                              // NOTE: If a ticket contains an error code in ticket.details.error, you
                              // must handle it appropriately. The error codes are listed in the Expo
                              // documentation:
                              // https://docs.expo.io/push-notifications/sending-notifications/#individual-errors
                              } catch (error) {
                              console.error(error);
                              }
                          }
                          })();
                    });
                    console.log(somePushTokens,'some Push Token')
                }
            })
            res.send({ success:true,rows:result.insertId }); // <---    
        }
    });
});

// Delete Order from database
app.get('/DeleteOrder', (req,res) => {
    var sql = "DELETE FROM orders WHERE id=?";
    conn.query(sql,[req.query.orderId], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            res.send({ success:true }); // <---
            console.log('Order Deleted');
        }
    });
});

// fetch orders
app.get('/fetchOrders', (req,res) => {
    var sql = "SELECT * FROM orders WHERE state=? AND date_ordered > ?";
    conn.query(sql,['pending',req.query.date], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (result.length > 0) {
                sql = "SELECT * FROM usersinfo WHERE latitude >= ? AND latitude <= ? AND longitude >= ? AND longitude <= ? AND id=? ORDER BY RAND() LIMIT 1";
                conn.query(sql,[req.query.backwardLatitude, req.query.forwardLatitude,req.query.backwardLongitude,req.query.forwardLongitude, result[0].customer_id], (err,response,fields) => {
                    if (err) {
                        res.send({ success:false });
                        console.log(err,'there has been an error');
                    } else {
                        res.send({ rows: { ...response[0] ,...result[0] }}); // <---
                    }
                });
            }
        }
    })
});


// fetch Currently Active user subscribed orders
app.get('/userSubActiveOrder', (req,res) => {
    var sql = "SELECT * FROM subscriptions WHERE customer_id=? AND next_cleaning_order>=? ORDER BY next_cleaning_order ASC LIMIT 1";
    conn.query(sql,[req.query.id,req.query.date], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] })   
            }else{
                res.send({ success:false,rows: null })   
            }
        }
    })
});

// fetch Currently Active Live orders
app.get('/fetchActiveOrder', (req,res) => {
    var sql = "SELECT * FROM orders WHERE id=?";
    conn.query(sql,[req.query.orderId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true,rows: result[0] })
        }
    })
});


// fetch Cleaner orders
app.get('/insertSubOrder', (req,res) => {
    var sql = "INSERT INTO cleanersuborders(sub_id,cleaner_id,date_ordered,end_of_order) VALUES(?,?,?,?)";
    conn.query(sql,[req.query.sub_id,req.query.cleaner_id,req.query.time,0], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true,rows: result })
        }
    })
});

// fetch Cleaner orders
app.get('/endSubOrder', (req,res) => {
    var sql = "UPDATE cleanersuborders SET end_of_order=? WHERE sub_id = ? AND date_ordered > ?";
    conn.query(sql,[req.query.end_time,req.query.sub_id,req.query.time], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true,rows: result })
        }
    })
});

// fetch Cleaner orders
app.get('/fetchExactEndOrder', (req,res) => {
    var sql = "SELECT * FROM cleanersuborders WHERE sub_id=? AND end_of_order > ? LIMIT 1";
    conn.query(sql,[req.query.sub_id,req.query.time], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result })   
            }else{
                res.send({ success:false,rows: result })
            }
        }
    })
});

// fetch Cleaner orders
app.get('/fetchExactStartedOrder', (req,res) => {
    var sql = "SELECT * FROM cleanersuborders WHERE cleaner_id=? AND date_ordered > ? AND sub_id=? AND end_of_order=? LIMIT 1";
    conn.query(sql,[req.query.cleaner_id,req.query.time,req.query.sub_id,0], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result })   
            }else{
                res.send({ success:false,rows: result })
            }
        }
    })
});

// fetch Cleaner orders
app.get('/fetchCleanerOrders', (req,res) => {
    var sql = "SELECT * FROM cleanersuborders WHERE cleaner_id=? ORDER BY date_ordered DESC";
    conn.query(sql,[req.query.cleanerId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true,rows: result })
        }
    })
});

// fetch Cleaner Subscriptions
app.get('/fetchCleanerSubscription', (req,res) => {
    var sql = "SELECT * FROM home_cleaners WHERE cleaner_id=? UNION ALL SELECT * FROM home_supervisors WHERE supervisor_id=?";
    conn.query(sql,[req.query.id,req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        }else {
            res.send({ success:true,rows:result  })
        }
    })
});

// Insert cleaner complaint
app.get('/cleanerComplaint', async(req,res) => {
    var sql = "INSERT INTO cleaner_complaint (cleaner_id,complaint) VALUES(?,?)";
    conn.query(sql,[req.query.cleaner_id,req.query.complaint], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            res.send({ success:true }); // <---
        }
    });
});

// fetch Agent orders
app.get('/fetchAgentOrders', (req,res) => {
    var sql = "SELECT * FROM agentsuborders WHERE agent_id=? ORDER BY date_ordered DESC";
    conn.query(sql,[req.query.agentId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (result.length > 0) {
                res.send({ success:false,rows: false })
            }else{
                res.send({ success:true,rows: result })
            }
        }
    })
});

// Check if user has an order
app.get('/checkIfUserHasOrder', (req,res) => {
    var sql = "SELECT * FROM orders WHERE customer_id=? AND state=?";
    conn.query(sql,[req.query.id,req.query.state], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Check if user has an order
app.get('/checkOrderStatus', (req,res) => {
    var sql = "SELECT * FROM orders WHERE id=? AND state=?";
    conn.query(sql,[req.query.orderId,req.query.state], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Check if user has an order
app.get('/getOrder', (req,res) => {
    var sql = "SELECT * FROM orders WHERE id=?";
    conn.query(sql,[req.query.orderId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});
// Check if user has an order
app.get('/checkOrderExist', (req,res) => {
    var sql = "SELECT * FROM orders WHERE id=?";
    conn.query(sql,[req.query.orderId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Register Cleaner in database
app.get('/registerCleaner', (req,res) => {
    var sql = "INSERT INTO cleaners (cleaner_id,nin,birth_info,availability,account_name,bank_name,account_number,invoice,rating,level,latitude,longitude) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";
    conn.query(sql,[req.query.id,req.query.nin,req.query.birthinfo,'true',req.query.accountName,req.query.bankname,req.query.banknumber,0,0,'recruit','',''], (err,results) => {
        if (err) {
            console.log(err,'There was an error')
            res.send({ success:false });
            return
        }else{
            sql = "UPDATE usersinfo SET role='worker' WHERE id=?"
            conn.query(sql,[req.query.id], (err,result) => {
                if (err) {
                    console.log(err,'there has been an error');
                    res.send({ success:false });
                } else {
                    sql = 'INSERT INTO work_period(cleaner_id,work_days,work_time) VALUES(?,?,?)'
                    conn.query(sql, [results.insertId, 'monday,tuesday,wednesday,thursday,friday,saturday,sunday', '6am,8am,10am,12pm,2pm,4pm'], (err, result) => {
                        res.send({ success:true }); // <---
                    })
                }
            })
        } 
    });
});

// Register Cleaner in database
app.get('/registerAgent', (req,res) => {
    var sql;
    sql = "SELECT * FROM agents WHERE cac_number=? OR agent_number=? OR account_number =?";
    conn.query(sql,[req.query.cacNumber,req.query.agentNumber,req.query.banknumber], (err,result,fields) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            if (result.length > 0) {
                res.send({ success:false })
            }else{
                sql = "INSERT INTO agents (company_name,cac_number,bio,account_name,bank_name,account_number,no_of_workers,ratings,agent_number,ssa,msa,lsa,elsa,deepCleaning,postConstruction) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
                conn.query(sql,[req.query.companyName,req.query.cacNumber,req.query.bio,req.query.accountName,req.query.bankname,req.query.banknumber,req.query.numberOfWorkers,0,req.query.agentNumber,0,0,0,0,0,0], (err,result) => {
                    if (err) {
                        console.log(err,'there has been an error');
                        res.send({ success:false });
                    } else {
                        res.send({ success:true,rows:result }); // <---
                    }
                });
            }
        }
    })
});

// Update Cleaner Hire Info
app.get('/UpdateHireInfo', (req,res) => {
    sql = "UPDATE cleaners SET ssa=?,msa=?,lsa=?,elsa=?,deepCleaning=? WHERE cleaner_id=?"
    conn.query(sql,[req.query.ssa,req.query.msa,req.query.lsa,req.query.elsa,req.query.deepCleaning,req.query.id], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            res.send({ success:true }); // <---
        }
    })
});

// Update Agent Hire Info
app.get('/UpdateAgentHireInfo', (req,res) => {
    sql = "UPDATE agents SET ssa=?,msa=?,lsa=?,elsa=?,deepCleaning=?,postConstruction=? WHERE id=?"
    conn.query(sql,[req.query.ssa,req.query.msa,req.query.lsa,req.query.elsa,req.query.deepCleaning,req.query.postConstruction,req.query.id], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            res.send({ success:true }); // <---
        }
    })
});

// Fetch cleaner
app.get('/fetchCleaner', (req,res) => {
    var sql = "SELECT * FROM cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Login Agent with CAC Number
app.get('/LoginAgent', (req,res) => {
    var sql = "SELECT * FROM agents WHERE cac_number=?";
    conn.query(sql,[req.query.cacNumber], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch Agent
app.get('/fetchAgent', (req,res) => {
    var sql = "SELECT * FROM agents WHERE id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch All Agents
app.get('/fetchAllAgent', (req,res) => {
    var sql = "SELECT * FROM agents";
    conn.query(sql, (err,Agentsresult,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (Agentsresult.length > 0) {
                var newResults = []
                for (let i = 0; i < Agentsresult.length; i++) {
                    sql = "SELECT COUNT(*) AS count FROM agentreviews WHERE agent_id=?";
                    conn.query(sql,Agentsresult[i].id, (err,result,fields) => {
                        newResults.push({ result:Agentsresult[i],count:result[0].count })
                        if (i + 1 === Agentsresult.length) {
                            res.send({ success:true,rows: newResults });
                        }
                    })
                }   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});


// Check if customer has ordered from an agent
app.get('/checkAllAgentOrders', (req,res) => {
    var sql = "SELECT * FROM agentsuborders WHERE agent_id=? AND customer_id=?";
    conn.query(sql,[req.query.agentId,req.query.customerId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Check if customer has made a review
app.get('/checkAllReviews', (req,res) => {
    var sql = "SELECT * FROM agentreviews WHERE agent_id=? AND customer_id=?";
    conn.query(sql,[req.query.agentId,req.query.customerId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Post Agent Review
app.get('/postReview', (req,res) => {
    var sql;
    sql = "INSERT INTO agentreviews (customer_id,agent_id,customer_name,review,ratings,dateofreview) VALUES(?,?,?,?,?,?)";
    conn.query(sql,[req.query.customerId,req.query.agentId,req.query.customerName,req.query.review,req.query.ratings,req.query.currentDate], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            sql = "UPDATE agents SET ratings=? WHERE id=?";
            conn.query(sql,[req.query.newAgentRating,req.query.agentId], (err,result) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there has been an error');
                } else {
                    res.send({ success:true }); // <---
                    console.log('updated');
                }
            });
        }
    });
});

// Post Agent Review
app.get('/postCleanerReview', (req,res) => {
    var sql = "INSERT INTO cleaner_reviews (customer_id,cleaner_id,customer_name,review,rating,dateofreview) VALUES(?,?,?,?,?,?)";
    conn.query(sql,[req.query.customerId,req.query.cleanerId,req.query.customerName,req.query.comment,req.query.rating,req.query.currentDate], (err,result) => {
        if (err) {
            console.log(err,'there has been an error');
            res.send({ success:false });
        } else {
            sql = "UPDATE cleaners SET rating=? WHERE cleaner_id=?";
            conn.query(sql,[req.query.totalRating,req.query.cleanerId], (err,result) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there has been an error');
                } else {
                    res.send({ success:true }); // <---
                    console.log('updated');
                }
            });
        }
    });
});

// Get All Agent Reviews
app.get('/getReviews', (req,res) => {
    var sql = "SELECT * FROM agentreviews WHERE agent_id=?";
    conn.query(sql,[req.query.agentId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Get All Cleaner Reviews
app.get('/getCleanerReviews', (req,res) => {
    var sql = "SELECT * FROM cleaner_reviews WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Count all reviews of an agent
app.get('/getReviewCount', (req,res) => {
    var sql = "SELECT COUNT(*) AS count FROM agentreviews WHERE agent_id=?";
    conn.query(sql,[req.query.agentId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            res.send({ success:true,rows: result[0] }); 
        }
    });
});

// Increase Cleaner Ratings
app.get('/increaseRating', (req,res) => {
    var sql = "UPDATE cleaners SET rating=? WHERE cleaner_id=?";
    conn.query(sql,[req.query.newRating,req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
        }
    });
});
// // Update users location
// app.get('/updateAgentRatings', (req,res) => {
//     var sql = "UPDATE agents SET ratings=? WHERE id=?";
//     conn.query(sql,[req.query.ratings,req.query.agentId], (err,result) => {
//         if (err) {
//             res.send({ success:false });
//             console.log(err,'there has been an error');
//         } else {
//             res.send({ success:true }); // <---
//             console.log('updated');
//         }
//     });
// });

// Update users location
app.get('/updateLocation', (req,res) => {
    var sql = "UPDATE usersinfo SET latitude=?, longitude=? WHERE id=?";
    conn.query(sql,[req.query.latitude,req.query.longitude,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
            console.log('updated');
        }
    });
});

// Update Cleaner location
app.get('/updateCleanerLocation', (req,res) => {
    var sql = "UPDATE cleaners SET latitude=?, longitude=? WHERE cleaner_id=?";
    conn.query(sql,[req.query.latitude,req.query.longitude,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
            console.log('Cleaner location updated');
        }
    });
});

// Update Cleaner WorkHours
app.get('/updateHirePeriod', (req,res) => {
    var sql = "UPDATE work_period SET work_days=?, work_time=? WHERE cleaner_id=?";
    conn.query(sql,[req.query.workDays,req.query.workTime,req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
            console.log('Cleaner WorkHours updated');
        }
    });
});

// Update Cleaner Availablility
app.get('/updateAvailablity', (req,res) => {
    var sql = "UPDATE cleaners SET availability=? WHERE cleaner_id=?";
    conn.query(sql,[req.query.available,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
            console.log('Cleaner WorkHours updated');
        }
    });
});

// Update userinfo from settings page
app.get('/updateUserInfo', (req,res) => {
    var sql = "UPDATE usersinfo SET email=?, firstname=?,lastname=? WHERE id=?";
    conn.query(sql,[req.query.email,req.query.firstname,req.query.lastname,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
            console.log('user info updated');
        }
    });
});

// Update user address
app.get('/updateUserAddress', (req,res) => {
    var sql = "UPDATE user_address SET street_number=?,street_name=?,city=?, estate=?, country=?, state=?, lga=? WHERE userid=?";
    conn.query(sql,[req.query.number,req.query.streetName,req.query.city,req.query.estate,req.query.country,req.query.state,req.query.lga,req.query.userid], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
            console.log('user address updated');
        }
    });
});

// Update Request Status for ordering
app.get('/updateOrderStatus', (req,res) => {
    var sql = "UPDATE orders SET state=?,cleaner_id=? WHERE id=?";
    conn.query(sql,[req.query.state,req.query.cleanerId,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
        }
    });
});

// Update Cleaner Invoice
app.get('/updateInvoice', (req,res) => {
    var sql = "SELECT invoice FROM cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,results) => {
        console.log(req.query.cleanerId)
        var totalInvoice = Number(results[0].invoice) + Number(req.query.invoice)
        sql = "UPDATE cleaners SET invoice=? WHERE cleaner_id=?";
        conn.query(sql,[totalInvoice,req.query.cleanerId], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there has been an error');
            } else {
                res.send({ success:true }); // <---
            }
        });
    })
});
// Get Cleaner Invoice
app.get('/getInvoice', (req,res) => {
    var sql = "SELECT invoice FROM cleaners WHERE cleaner_id=? AND invoice >= ?";
    conn.query(sql,[req.query.cleanerId,req.query.invoice], (err,results) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (results.length > 0) {
                res.send({ success:true,rows:results[0] });   
            }else{
                res.send({ success:false });
            }
        }
    })
});
// Get Cleaner Bank Info
app.get('/getBankInfo', (req,res) => {
    var sql = "SELECT account_name,bank_name,account_number FROM cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.id], (err,results) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (results.length > 0) {
                res.send({ success:true,rows:results[0] });   
            }else{
                res.send({ success:false });
            }
        }
    })
});

// Get Agent Bank Info
app.get('/getAgentBankInfo', (req,res) => {
    var sql = "SELECT account_name,bank_name,account_number FROM agents WHERE id=?";
    conn.query(sql,[req.query.agentId], (err,results) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            if (results.length > 0) {
                res.send({ success:true,rows:results[0] });   
            }else{
                res.send({ success:false });
            }
        }
    })
});

app.get('/updateBankInfo', (req,res) => {
    var sql = "UPDATE cleaners SET account_name=?,bank_name=?,account_number=? WHERE cleaner_id=?";
    conn.query(sql,[req.query.accountName,req.query.bankName,req.query.accountNumber,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
        }
    });
});

app.get('/updateAgentBankInfo', (req,res) => {
    var sql = "UPDATE agents SET account_name=?,bank_name=?,account_number=? WHERE id=?";
    conn.query(sql,[req.query.accountName,req.query.bankName,req.query.accountNumber,req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there has been an error');
        } else {
            res.send({ success:true }); // <---
        }
    });
});
// // Update availabilty Status for Cleaner
// app.get('/updateCleanerAvailability', (req,res) => {
//     var sql = "UPDATE cleaners SET availability=? WHERE cleaner_id=?";
//     conn.query(sql,[req.query.availability,req.query.cleanerId], (err,result) => {
//         if (err) {
//             res.send({ success:false });
//             console.log(err,'there has been an error');
//         } else {
//             res.send({ success:true }); // <---
//             console.log('availablility updated');
//         }
//     });
// });




// Get user info
app.get('/GetId', (req,res) => {
    var sql = "SELECT * FROM usersinfo WHERE id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err)
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] }); // <---   
            }else{
                res.send({ success:false }); // <---
            }
        }
    });
});

// Get user address
app.get('/fetchUserAddress', (req,res) => {
    var sql = "SELECT * FROM user_address WHERE userid=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err)
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] }); // <---   
            }else{
                res.send({ success:false }); // <---
            }
        }
    });
});
// Get user info through email for Login
app.get('/FetchUserInfo', async(req,res) => {
    var sql = "SELECT * FROM usersinfo WHERE email=?";
    conn.query(sql,[req.query.email], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err)
        } else {
            if (result.length > 0) {
                bcrypt.compare(req.query.password,result[0].password).then((auth) => {
                    if (auth) {
                        res.send({ success: true,rows: result[0] });
                    }else{
                        res.send({ success: false,error:'wrongPassword' });
                    }
                })   
            }else if(result.length < 1){
                res.send({ success: false,error:'noEmail' });
            }else{
                res.send({ success: false,error:'error' });
            }
        }
    });
});

// Get cleaner info through email for Login
app.get('/FetchCleanerInfo', async(req,res) => {
    var sql = "SELECT * FROM usersinfo WHERE email=?";
    conn.query(sql,[req.query.email], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err)
        } else {
            if (result.length > 0) {
                sql = "SELECT cleaner_id FROM cleaners WHERE cleaner_id=?";
                conn.query(sql, [result[0].id], (err,results) => {
                    if (err) {
                        res.send({ success:false });
                        console.log(err)
                    }else if (results.length < 1) {
                        res.send({ success:false,error:'NoCleaner' });
                    }else{
                        bcrypt.compare(req.query.password,result[0].password).then((auth) => {
                            if (auth) {
                                res.send({ success: true,rows: result[0] });
                            }else{
                                res.send({ success: false,error:'wrongPassword' });
                            }
                        }) 
                    }
                })  
            }else if(result.length < 1){
                res.send({ success: false,error:'noEmail' });
            }else{
                res.send({ success: false,error:'error' });
            }
        }
    });
});

// Fetch Customer Location
app.get('/getCustomerLocation', (req,res) => {
    var sql = "SELECT * FROM usersinfo WHERE id=?";
    conn.query(sql,[req.query.customerId], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        }else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch Cleaner Location
app.get('/getCleanerLocation', (req,res) => {
    var sql = "SELECT latitude,longitude FROM cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        }else {
            if (result.length > 0) {
                res.send({ success:true,row: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch subscriptions
app.get('/fetchSubscription', (req,res) => {
    var sql = "SELECT * FROM subscriptions WHERE customer_id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch subscriptions
app.get('/fetchSubscriptionById', (req,res) => {
    var sql = "SELECT * FROM subscriptions WHERE id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result[0] });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch ALL HIRED CLEANERS FOR A PARTICULAR USER/CUSTOMER subscriptions
app.get('/fetchHiredCleaners', (req,res) => {
    var sql = "SELECT cleaner_id,cleaner_name FROM subscriptions WHERE customer_id=? AND cleaner_id > 0";
    conn.query(sql,[req.query.userid], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Insert instructions
app.get('/updateInstructions', (req,res) => {
    var sql = "INSERT INTO instructions(customer_id,space,instruction) VALUES(?,?,?)";
    conn.query(sql,[req.query.id,req.query.space,req.query.instruction], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            res.send({ success:true,rows: result });   
        }
    });
});

// Fetch instructions
app.get('/deleteInstruction', (req,res) => {
    var sql = "DELETE FROM instructions WHERE customer_id=? AND space=? AND instruction=?";
    conn.query(sql,[req.query.id,req.query.space,req.query.instruction], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// Fetch instructions
app.get('/fetchInstructions', (req,res) => {
    var sql = "SELECT * FROM instructions WHERE customer_id=?";
    conn.query(sql,[req.query.id], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// fetch job Progress for today
app.get('/fetchSpaceProgress', (req,res) => {
    var sql = "SELECT * FROM job_completion WHERE sub_id=? AND timestamp > ?";
    conn.query(sql,[req.query.sub_id,req.query.time], (err,result,fields) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error checking if user has an order')
        } else {
            if (result.length > 0) {
                console.log(result,'result')
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows:false });
            }
        }
    });
});

// check if user has subscribed
app.get('/checkIfUserPaid', (req,res) => {
   var sql = "SELECT id FROM subscriptions WHERE customer_id=? AND amount=? AND deadline > ? LIMIT 1"
   conn.query(sql, [req.query.userid,req.query.amount,req.query.date], (err, result) => {
    if (err) {
        res.send({ success:false })
    }else{
        if (result.length > 0) {
            res.send({ success:true,row: result[0] });   
        }else{
            res.send({ success:false,row:false });
        }
    }
   })
});

// postpone cleaning date
app.get('/postponeCleaning', (req,res) => {
   var sql = "UPDATE subscriptions SET next_cleaning_order=? WHERE id=?"
   conn.query(sql, [req.query.date,req.query.id], (err, result) => {
    if (err) {
        res.send({ success:false })
    }else{
        if (result.length > 0) {
            res.send({ success:true,rows: result });   
        }else{
            res.send({ success:false,rows:false });
        }
    }
   })
});

// Unsubscribe User
app.get('/cancelSub', (req,res) => {
   var sql = "SELECT sub_code,customer_email FROM subscriptions WHERE id=?"
   conn.query(sql, [req.query.subscription_id], (err, result) => {
    if (err) {
        res.send({ success:false })
    }else{
        if (result.length > 0) {
            paystack.subscription.disable({
                code: result[0].sub_code,
                token:result[0].customer_email
            })
            .then(function(error, body) {
               sql = "DELETE FROM subscriptions WHERE id=?"
               conn.query(sql, [req.query.subscription_id], (err, result) => {
                    if (err) {
                        console.log(err)
                        res.send({ success:false,err })
                    }else{
                        sql = "INSERT INTO cancellation_reason(userid,reason) VALUES(?,?)"
                        conn.query(sql, [req.query.userid,req.query.reason], (err, result) => {
                            if (err) {
                                console.log(err)
                                res.send({ success:false,err })
                            }else{
                                res.send({ success:true })
                            }
                        })
                    }
               })
               sql = "DELETE FROM home_cleaners WHERE sub_id=?"
               conn.query(sql, [req.query.subscription_id])
               sql = "DELETE FROM home_supervisors WHERE sub_id=?"
               conn.query(sql, [req.query.subscription_id])
            })
            .catch(err => {
                res.send({ success:false, err })
            })   
        }else{
            res.send({ success:false,rows:false });
        }
    }
   })
});

app.get('/paystackCallback', (req,res) => {
    var sql = "INSERT INTO subscriptions(type,sub_interval,cleaner_id,cleaner_name,customer_id,customer_name,customer_email,cleaning_interval,cleaning_interval_frequency,amount,cleaner_pay,supervisor_pay,places,bonus,special_treatment,day_period,time_period,sub_code,state,country,deadline,next_cleaning_order,next_deep_clean,next_special_treatment,num_of_supervisor,num_of_cleaner,available,discount_percentage) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
     conn.query(sql, ['home',req.query.subInterval,0,'',req.query.customerId,req.query.customer_name,req.query.email,req.query.cleaningInterval,req.query.cleaningIntervalFrequency,req.query.amount,req.query.cleaner_pay,req.query.supervisor_pay,req.query.places,req.query.bonus,req.query.special_treatment,'','','',req.query.state,req.query.country,req.query.deadline,req.query.date,req.query.date,req.query.date,req.query.supervisor,req.query.cleaner,'true',req.query.discount], (err, result) => {
        if (err) {
            console.log(err)
           res.send({ success:false })
        }else{
            sql = "SELECT userid FROM user_address WHERE state=?"
            conn.query(sql, [req.query.state], (err, result) => {
                if (err) {
                    console.log(err)
                }else{
                    for (let i = 0; i < result.length; i++) {
                        sql = "SELECT id FROM cleaners WHERE cleaner_id=?"
                        conn.query(sql, [result[i].userid], (err, result) => {
                            if (err) {
                                console.log(err)
                            }else{
                                var message = { 
                                    app_id: `${oneSignalAppId}`,
                                    contents: {"en": "There's a new order available. Apply quickly!!!"},
                                    headings: {"en": `You have a new order`},
                                    channel_for_external_user_ids: "push",
                                    include_external_user_ids: [`${result[i].userid}`]
                                };
                                sendNotification(message)
                            }
                        })   
                    }
                }
            })
           res.send({ success:true })
        }
    })
});

app.get('/fetchCustomPlan', (req,res) => {
    var sql = "SELECT * FROM custom_plan WHERE userid=?";
    conn.query(sql, [req.query.id], (err, result) => {
        if (err) {
            res.send({ success:false })
        }else{
            res.send({ success:true,row:result })
        }
    })
})

// Update Custom Plan
// app.get('/updateCustomPlan', (req,res) => {
//     var sql = "UPDATE custom_plan SET plan_name=? AND plan_desc=? WHERE userid=?";
//     conn.query(sql, [req.query.plan_name,req.query.plan_desc,req.query.id], (err, result) => {
//         if (err) {
//             res.send({ success:false })
//         }else{
//             res.send({ success:true })
//         }
//     })
// })

// fetch Plan name and description
app.get('/fetchPlanInfo', (req,res) => {
    var sql = "SELECT * FROM plan_info WHERE sub_id=?";
    conn.query(sql, [req.query.sub_id], (err, result) => {
        if (err) {
            res.send({ success:false })
        }else{
            if(result.length > 0){
                res.send({ success:true,row:result })
            }else{
                res.send({ success:false,row:'empty' })
            }
        }
    })
})

// Insert Plan name and description
app.get('/insertPlanInfo', (req,res) => {
    var sql = "INSERT INTO plan_info(sub_id,plan_name,plan_desc) VALUES(?,?,?)";
    conn.query(sql, [req.query.sub_id,req.query.name,req.query.desc], (err, result) => {
        if (err) {
            res.send({ success:false })
        }else{
            res.send({ success:true,row:result })
        }
    })
})

app.get('/updateSubscriptionOrder', (req,res) => {
    var sql = "UPDATE subscriptions SET next_cleaning_order=?,day_period=?,time_period=? WHERE id=?";
    conn.query(sql, [req.query.date,req.query.dayPeriod,req.query.timePeriod,req.query.id], (err, result) => {
        if (err) {
            res.send({ success:false })
        }else{
            res.send({ success:true,row:result })
        }
    })
})

// 
 app.get('/updateCustomPlan', (req,res) => {
    var sql = "SELECT userid FROM custom_plan WHERE userid=?";
    conn.query(sql, [req.query.id], (err, result) => {
        if (err) {
            res.send({ success:false })
        }else{
            if (result.length > 0) {
                console.log(req.query.step,'step')
                var sql = "UPDATE custom_plan SET userid=?,amount=?,cleaning_days=?,time_period=?,sub_interval=?,places=?,cleaning_interval=?,cleaning_frequency=?,setup_step=? WHERE userid=?";
                conn.query(sql,[req.query.id,req.query.amount,req.query.days,req.query.time_period,req.query.subInterval,req.query.places,req.query.cleaningInterval,req.query.cleaningFrequency,req.query.step,req.query.id], (err,result) => {
                    if (err) {
                        res.send({ success:false });
                        console.log(err,'there has been an error');
                    } else {
                        res.send({ success:true }); // <---
                    }
                });
            }else{
                var sql = "INSERT INTO custom_plan(userid,amount,cleaning_days,time_period,sub_interval,places,cleaning_interval,cleaning_frequency,setup_step) VALUES(?,?,?,?,?,?,?,?,?)";
                conn.query(sql,[req.query.id,req.query.amount,req.query.plan_name,req.query.desc,req.query.days,req.query.time_period,req.query.subInterval,req.query.places,req.query.cleaningInterval,req.query.cleaningFrequency,req.query.step], (err,result) => {
                    if (err) {
                        res.send({ success:false });
                        console.log(err,'there has been an error');
                    } else {
                        res.send({ success:true }); // <---
                    }
                });
            }
        }
    })
});

// Subsribe to plan from premade plan
app.get('/subscribeToPlan', (req,res) => {
    var sql = "SELECT plan_code FROM plans WHERE id=?"
    conn.query(sql, [req.query.plan_id], (err, result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        } else {
            paystack.transaction.initialize({
                callback_url:`${AllKeys.ipAddress}/paystackCallback?discount=${req.query.discount}&cleaner_pay=${req.query.cleaner_pay}&supervisor_pay=${req.query.supervisor_pay}&special_treatment=${req.query.special_treatment}&date=${''}&cleaner=${req.query.cleaner}&supervisor=${req.query.supervisor}&subInterval=monthly&deadline=${req.query.deadline}&customer_name=${req.query.customer_name}&state=${req.query.state}&country=${req.query.country}&email=${req.query.email}&places=${req.query.places}&amount=${req.query.amount}&customerId=${req.query.id}&cleaningInterval=${req.query.cleaningInterval}&day_period=${req.query.day_period}&time_period=${req.query.time_period}&cleaningIntervalFrequency=${req.query.cleaningIntervalFrequency}&bonus=${req.query.bonus}`,
                email: `${req.query.email}`,
                amount:`${req.query.amount}`,
                currency: 'NGN',
                plan: result[0].plan_code
            })
            .then(response => {
                if (response.status) {
                    res.send({ success:true, url: response.data.authorization_url })   
                }else{
                    res.send({ success:false, url: null })
                }
            }).catch(err => {
                console.log(err)
            })   
        }
    })
});

// User Just subscribed
app.get('/InserthasSubscribed', (req,res) => {
    var sql = "SELECT id FROM has_subscribed WHERE userid=?"
    conn.query(sql, [req.query.id], (err,result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            if (result.length > 0) {
                sql = "UPDATE has_subscribed SET timestamp=? WHERE userid=?"
                conn.query(sql, [req.query.time,req.query.id], (err,result) => {
                    if (err) {
                        console.log(err)
                        res.send({ success:false })
                    }else{
                        res.send({ success:true })
                    }
                })
            }else{
                var sql = "INSERT INTO has_subscribed(userid,timestamp) VALUES(?,?)";
                conn.query(sql,[req.query.id,req.query.time], (err,result) => {
                    if (err) {
                        res.send({ success:false });
                        console.log(err,'there was an error inserting link')
                    }else {
                        res.send({ success:true });
                    }
                });
            }
        }
    })
});

// Check if user has subscribed
app.get('/hasSubscribed', (req,res) => {
    var sql = "SELECT id FROM has_subscribed WHERE userid=?"
    conn.query(sql, [req.query.id], (err,result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            if (result.length > 0) {
                res.send({ success:true })
            }else{
                res.send({ success:false })
            }
        }
    })
});

// Create Subscription Plan
app.get('/createPlan', (req,res) => {
    var sql = "SELECT plan_code FROM plans WHERE name=?";
    conn.query(sql, [req.query.name], (err, result) => {
        if (err) {
            res.send({ success:false })
        }else if (result.length > 0) {
            paystack.transaction.initialize({
                callback_url:`${AllKeys.ipAddress}/paystackCallback?discount=${req.query.discount}&special_treatment=${req.query.special_treatment}&supervisor_pay=${req.query.supervisorPay}&cleaner_pay=${req.query.cleanerPay}&date=${''}&deadline=${req.query.deadline}&customer_name=${req.query.customer_name}&state=${req.query.state}&country=${req.query.country}&supervisor=${req.query.supervisor}&cleaner=${req.query.cleaner}&email=${req.query.email}&places=${req.query.places}&amount=${req.query.amount}&customerId=${req.query.customerId}&cleaningInterval=${req.query.cleaningInterval}&day_period=${''}&time_period=${''}&cleaningIntervalFrequency=${req.query.cleaningIntervalFrequency}&bonus=${req.query.bonus}&subInterval=${req.query.subInterval}`,
                email: `${req.query.email}`,
                amount: req.query.amount * 100,
                interval: `${req.query.subInterval}`,
                currency: 'NGN',
                plan: result[0].plan_code
            })
            .then(response => {
                if (response.status) {
                    res.send({ success:true, url: response.data.authorization_url })   
                }else{
                    res.send({ success:false, url: null,error:response.message })
                }
            }).catch(err => {
                console.log(err)
                res.send({ success:false,url:null })
            })
        }else{
            paystack.plan.create({
                name: `${req.query.name}`,
                amount: req.query.amount * 100,
                interval: `${req.query.subInterval}`
              })
            .then(function(response, body) {
                if (!response.status) {
                    console.log(response);
                    res.send({ success:false })
                }else{
                    var sql = "INSERT INTO plans(name,plan_code,plan_interval,amount) VALUES(?,?,?,?)";
                    conn.query(sql,[req.query.name,response.data.plan_code,req.query.subInterval,req.query.amount], (err,result,fields) => {
                        if (err) {
                            res.send({ success:false });
                            console.log(err,'there was an error checking if user has an order')
                        } else {
                            paystack.transaction.initialize({
                                callback_url: `${AllKeys.ipAddress}/paystackCallback?discount=${req.query.discount}&special_treatment=${req.query.special_treatment}&email=${req.query.email}&deepCleaning=${req.query.deepCleaning}&places=${req.query.places}&amount=${req.query.amount}&time_period=${req.query.time_period}&customerId=${req.query.customerId}&cleaningInterval=${req.query.cleaningInterval}&day_period=${req.query.day_period}&time_period=${req.query.time_period}&cleaningIntervalFrequency=${req.query.cleaningIntervalFrequency}&bonus=${req.query.bonus}&subInterval=${req.query.subInterval}`,
                                email: `${req.query.email}`,
                                amount: req.query.amount * 100,
                                interval: `${req.query.subInterval}`,
                                currency: 'NGN',
                                plan: response.data.plan_code
                            })
                            .then(response => {
                                if (response.status) {
                                    res.send({ success:true, url: response.data.authorization_url })   
                                }else{
                                    res.send({ success:false, url: null })
                                }
                            }).catch(err => {
                                console.log(err)
                                res.send({ success:false,url:null })
                            })
                        }
                    });
                }
            });
        }
    })
});
// export const updateUser = (latitude,longitude) => new Promise((resolve, reject) => {
//     if (err) {
//         return reject(err)
//     }else{
        
//     }
// })

// Blipmoore cleaner only code

// Fetch create signupLink for employee
app.get('/createEmployeeLink', (req,res) => {
    var sql = "INSERT INTO employee_signup_link(password,role,timestamp) VALUES(?,?,?)";
    conn.query(sql,[req.query.randString,req.query.role,req.query.timestamp], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,row: result.insertId });
        }
    });
});

// Employ or add cleaner to enterprise
app.get('/applyToEnterprise', (req,res) => {
    var sql = ''
    if (req.query.role === 'supervisor') {
        sql = "INSERT INTO enterprise_supervisor(supervisor_id,enterprise_id) VALUES(?,?)"
        conn.query(sql, [req.query.cleaner_id,req.query.enterprise_id], (err,result) => {
            if (err) {
                console.log(err)
            }
        })   
    }else if (req.query.role === 'cleaner') {
        sql = "INSERT INTO enterprise_cleaners(cleaner_id,enterprise_id) VALUES(?,?)"
        conn.query(sql, [req.query.cleaner_id,req.query.enterprise_id], (err,result) => {
            if (err) {
                console.log(err)
            }
        })
    }
    sql = "SELECT * FROM occupied_workperiod WHERE cleaner_id=?"
    conn.query(sql, [req.query.cleaner_id], (err,result) => {
        if (!err) {
            if (result.length > 0) {
                var dayArr = result[0].day_period.split(',').filter(day => !req.query.day_period.includes(day))
                var timeArr = result[0].time_period.split(',').filter(time => !req.query.time_period.includes(time))
                sql = "UPDATE occupied_workperiod SET day_period=? AND time_period=? WHERE cleaner_id=?"
                conn.query(sql, [dayArr,timeArr,req.query.cleaner_id], (err,result) => {
                    if (err) {
                        console.log(err)
                    }else{
                        res.send({ success:true })
                    }
                })
            }else{
                sql = "INSERT INTO occupied_workperiod(cleaner_id,day_period,time_period) VALUES(?,?,?)"
                conn.query(sql, [req.query.cleaner_id,req.query.day_period,req.query.time_period], (err,result) => {
                    if (err) {
                        console.log(err)
                    }else{
                        res.send({ success:true })
                    }
                })
            }
        }
    })
});

// Employ trainee
app.get('/employTrainee', (req,res) => {
    var sql = "INSERT INTO trainee(trainee_id,sub_id) VALUES(?,?)";
    conn.query(sql, [req.query.trainee_id,req.query.sub_id], (err, result) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            sql = "SELECT id FROM trainee_occupied_workdays WHERE trainee_id=?"
            conn.query(sql, [req.query.trainee_id], (err, result) => {
                if (err) {
                    res.send({ success:false })
                }else{
                    var dayArr = result[0].day_period.split(',').filter(day => !req.query.day_period.includes(day))
                    if (result.length > 0) {
                        sql = "UPDATE trainee_occupied_workdays SET days=? WHERE trainee_id=?"
                        conn.query(sql, [days, req.query.trainee_id], (err, result) => {
                            if (err) {
                                res.send({ success:false })
                            }else{
                                res.send({ success:true })
                            }
                        })
                    }else{
                        sql = "INSERT INTO trainee_occupied_workdays(trainee_id,days) VALUES(?,?)"
                        conn.query(sql, [req.query.trainee_id,req.query.day_period], (err, results) => {
                            if (err) {
                                console.log(err)
                                res.send({ success:false })
                            }else{
                                res.send({ success:true })
                            }
                        })
                    }
                }
            })
        }
    })
})

// Employ or add cleaner to enterprise
app.get('/applyToHome', (req,res) => {
    if (Number(req.query.cleanersNum) < 2) {
        var sql = "UPDATE subscriptions SET available=? WHERE id=?"
        conn.query(sql, ['false', req.query.sub_id])
    }
    if (req.query.role === 'cleaner') {
        var sql = "INSERT INTO home_cleaners(sub_id,cleaner_id) VALUES(?,?)";
        conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                var message = { 
                    app_id: `${oneSignalAppId}`,
                    contents: {"en": "A new cleaner has been assigned to you"},
                    headings: {"en": `Order ${req.query.sub_id} update`},
                    channel_for_external_user_ids: "push",
                    include_external_user_ids: [`${req.query.cus_id}`]
                };
                sendNotification(message)
                res.send({ success:true});
            }
        });
    }else if(req.query.role === 'supervisor'){
        var message = {
            app_id: `${oneSignalAppId}`,
            contents: {"en": "A new supervisor has been assigned to you"},
            headings: {"en": `Order ${req.query.sub_id} update`},
            channel_for_external_user_ids: "push",
            include_external_user_ids: [`${req.query.cus_id}`]
        };
        // This is to check whether a supervisor has previously applied
        if (req.query.num_of_supervisor === req.query.supervisorSlotsLeft) {
            var sql = "UPDATE subscriptions SET cleaner_id=?,cleaner_name=? WHERE id=?";
            conn.query(sql,[req.query.cleaner_id,req.query.cleanerName,req.query.sub_id], (err,result) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there was an error inserting link')
                }else {
                    sql = "INSERT INTO home_supervisors(sub_id,supervisor_id) VALUES(?,?)";
                    conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (err,result) => {
                        if (err) {
                            res.send({ success:false });
                            console.log(err,'there was an error inserting link')
                        }else {
                            res.send({ success:true});
                        }
                    });
                }
            });
        }else{
            var sql = "INSERT INTO home_supervisors(sub_id,supervisor_id) VALUES(?,?)";
            conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (err,result) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there was an error inserting link')
                }else {
                    res.send({ success:true});
                }
            });
        }
        sendNotification(message)
    }
    sql = "SELECT * FROM occupied_workperiod WHERE cleaner_id=?"
    conn.query(sql, [req.query.cleaner_id], (err,result) => {
        if (!err) {
            if (result.length > 0) {
                var diff = _.difference(req.query.day_period.split(','),result[0].day_period.split(','))
                var str = result[0].day_period + ',' + diff
                sql = "UPDATE occupied_workperiod SET day_period=? WHERE cleaner_id=?"
                conn.query(sql, [str,req.query.cleaner_id], (err,result) => {
                    if (err) {
                        console.log(err)
                    }
                })
            }else{
                sql = "INSERT INTO occupied_workperiod(cleaner_id,day_period,time_period) VALUES(?,?,?)"
                conn.query(sql, [req.query.cleaner_id,req.query.day_period,req.query.time_period], (err,result) => {
                    if (err) {
                        console.log(err)
                    }
                })
            }
        }
    })
});

// Quit from enterprise from being a cleaner
app.get('/quitHome', (req,res) => {
    var sql = "SELECT id,customer_id FROM subscriptions WHERE cleaner_id=? AND id=?"
    conn.query(sql, [req.query.cleaner_id,req.query.sub_id], (err,results) => {
        if (err) {
            console.log(err)
            res.send({ success:false })
        }else{
            if (results.length > 0) {
                sql = "UPDATE subscriptions SET cleaner_id=? AND cleaner_name=? WHERE id=?"
                conn.query(sql, [0,'', req.query.sub_id])
            }
            sql = "UPDATE subscriptions SET available=? WHERE id=?"
            conn.query(sql, ['true', req.query.sub_id], (err, result) => {
                if (err) {
                    console.log(err)
                }
            })
            sql = "SELECT day_period FROM occupied_workperiod WHERE cleaner_id=?"
            conn.query(sql, [req.query.cleaner_id], (err, result) => {
                if (err) {
                    console.log(err)
                }else{
                    var dayArr = result[0].day_period.split(',').filter(day => !req.query.day_period.includes(day))
                    var dayStr = ''
                    for (let i = 0; i < dayArr.length; i++) {
                        if (dayStr.length > 0) {
                            dayStr += ',' + dayArr[i]    
                        }else{
                            dayStr += dayArr[i] 
                        }
                    }
                    sql = "UPDATE occupied_workperiod SET day_period=? WHERE cleaner_id=?"
                    conn.query(sql, [dayStr, req.query.cleaner_id], (err, result) => {
                        if (err) {
                            console.log(err)
                        }
                    })
                }
            })
            sql = "DELETE FROM home_supervisors WHERE sub_id=? AND supervisor_id=?";
            conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (err,result) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there was an error inserting link')
                }else {
                    sql = "DELETE FROM home_cleaners WHERE sub_id=? AND cleaner_id=?";
                    conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (err,result) => {
                        if (err) {
                            res.send({ success:false });
                            console.log(err,'there was an error inserting link')
                        }else {
                            res.send({ success:true,row: result });
                        }
                    });
                    sql = "SELECT customer_id FROM subscriptions WHERE id=?"
                    conn.query(sql, [req.query.sub_id], (err, result) => {
                        if (err) {
                            console.log(err)
                        }else{
                            var message = { 
                                app_id: `${blipmoore_oneSignalAppId}`,
                                contents: {"en": "Your current cleaner has been removed"},
                                headings: {"en": `Order ${req.query.sub_id} update`},
                                channel_for_external_user_ids: "push",
                                include_external_user_ids: [`${result[0].customer_id}`]
                            };
                            sendNotification(message,'blipmoore')
                        }
                    })
                }
            });
        }
    })
});

// Quit from enterprise from being a supervisor
app.get('/quitEnterprise', (req,res) => {
    var sql = "DELETE FROM enterprise_supervisor WHERE enterprise_id=? AND supervisor_id=?";
    conn.query(sql,[req.query.enterprise_id,req.query.supervisor_id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            sql = "DELETE FROM enterprise_cleaners WHERE enterprise_id=? AND cleaner_id=?";
            conn.query(sql,[req.query.enterprise_id,req.query.cleaner_id], (err,result) => {
                if (err) {
                    res.send({ success:false });
                    console.log(err,'there was an error inserting link')
                }else {
                    console.log(result)
                    res.send({ success:true,row: result });
                }
            });
        }
    });
});

// 
app.get('/encode', (req,res) => {
    var b = Buffer.from(req.query.string)
    var s = b.toString('base64');
    res.send(s)
});
app.get('/readFileName', (req,res) => {
   const fileName = path.basename(req.query.uri)
    res.send(fileName)
});

// Fetch cleaner current active order 
app.get('/fetchCurrentOrder', (req,res) => {
    var arr= []
    let promises = []
    var allEntId = []
    var allSubId = []
    promises.push(
    new Promise(resolve => {
    var sql = "SELECT enterprise_id FROM enterprise_cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            allEntId.push(...result)
            sql = "SELECT enterprise_id FROM enterprise_supervisor WHERE supervisor_id=?";
            conn.query(sql, [req.query.cleanerId], (err, result) => {
                if (err) {
                    console.log(err)
                    res.send({ success:false })
                }else{
                    allEntId.push(...result)
                    for (let i = 0; i < allEntId.length; i++) {
                        sql = `SELECT * FROM enterprise WHERE id=? AND FIND_IN_SET('${req.query.day}', day_period) > 0`;
                        conn.query(sql, [allEntId[i].enterprise_id], (err,results) => {
                            if (err) {
                                console.log(err,'err')
                                res.send({ success:false })
                            }else{
                                if (results.length > 0) {
                                    i = i + allEntId.length
                                    arr.push({ cooperate:results,home:false,rows: results })
                                    resolve(results)
                                }else if (i + 1 === allEntId.length) {
                                    resolve(results)
                                }
                            }
                        })  
                    }
                }
            })
        }
    });
}))
    Promise.all(promises).then((results) => {
        var cusId = ''
        var sql = "SELECT sub_id FROM home_cleaners WHERE cleaner_id=?";
        conn.query(sql,[req.query.cleanerId], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                allSubId.push(...result)
                sql = "SELECT sub_id FROM home_supervisors WHERE supervisor_id=?";
                conn.query(sql, [req.query.cleanerId], (err, result) => {
                    if (err) {
                        console.log(err)
                        res.send({ success:false })
                    }else{
                        allSubId.push(...result)
                        for (let i = 0; i < allSubId.length; i++) {
                            if (cusId.length > 0) {
                                cusId += ',' + allSubId[i].sub_id
                            }else{
                                cusId += allSubId[i].sub_id
                            }
                        }
                        sql = `SELECT * FROM subscriptions WHERE id IN ('${cusId}') AND next_cleaning_order > ? ORDER BY next_cleaning_order ASC LIMIT 1`;
                            conn.query(sql, [req.query.date], (err,response) => {
                                var obj = {
                                    home: true,
                                    success:true,
                                    rows:response
                                }
                                if (err) {
                                    console.log(err,'err')
                                    res.send({ success:false })
                                }else{
                                    if (response.length > 0) {
                                        if (arr.length > 0) {
                                           arr = arr.map(val => ({...val, ...obj}))
                                           res.send(arr[0])
                                       }else{
                                           res.send({ home:true,success:true,cooperate:false,rows:response })
                                       }
                                   }else{
                                       if (arr.length > 0) {
                                           arr = arr.map(val => ({...val, success:true,home:false, cooperate:true}))
                                           res.send(arr[0])
                                       }else{
                                           res.send({ home:false,success:true,cooperate:false,rows:response })
                                       }
                                   }
                                }
                            }) 
                    }
                })
            }
        });
    })
});

// Update / insert job status and completion
app.get('/updateJobCompleted', (req,res) => {
    if (req.query.status === 'started') {
        var sql = "INSERT INTO job_completion(sub_id,cleaner_id,cleaner_name,place,place_number,status,timestamp,progress_bar) VALUES(?,?,?,?,?,?,?,?)";
        conn.query(sql,[req.query.orderId,req.query.cleaner_id,req.query.cleaner_name,req.query.place,req.query.place_num,req.query.status,req.query.time,req.query.progress_bar], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                res.send({ success:true });
            }
        });
    }else if(req.query.status === 'done'){
        var sql = "UPDATE job_completion SET status=?,progress_bar=? WHERE sub_id=? AND cleaner_id=? AND timestamp > ? AND timestamp < ? AND place_number=? AND place =? ";
        conn.query(sql,[req.query.status,req.query.progress_bar,req.query.orderId,req.query.cleaner_id,req.query.startOfDaytime,req.query.time,req.query.place_num,req.query.place], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                sql = "INSERT INTO sub_job_invoice_status(sub_id,supervisor_id,cleaner_id,amount,status,timestamp) VALUES(?,?,?,?,?,?)"
                conn.query(sql, [req.query.orderId,req.query.supervisor_id,req.query.cleaner_id,req.query.amount,'awaiting',req.query.time], (err, result) => {
                    if (err) {
                        console.log(err)
                    } 
                    res.send({ success:true });
                })
            }
        });
    }
});
// delete Job Progress by Supervisor
app.get('/deleteJobProgress', (req,res) => {
    var sql = "DELETE FROM job_completion WHERE sub_id=? AND cleaner_id=? AND place=? AND place_number=? AND timestamp < ? AND timestamp > ?"
    conn.query(sql, [req.query.sub_id,req.query.cleaner_id,req.query.place,req.query.place_num,req.query.time,req.query.startOfDaytime], (err, result) => {
        if (err) {
            console.log(err,'there has been an error')
            res.send({ success:false })
        }else{
            res.send({ success:true })
        }
    })
})

// Fetch available enterprise 
app.get('/getRequests', (req,res) => {
    var timestr = ''
    var sql = "SELECT * FROM occupied_workperiod WHERE cleaner_id=?"
    conn.query(sql, [req.query.cleaner_id], (err,result) => {
        if (!err) {
            if (result.length > 0) {
                // You look for the difference from the cleaner work days - the occupied time/days
               var dayDiff = _.difference(req.query.day_period.split(','),result[0].day_period.split(','))
            //    var timeDiff = _.difference(req.query.time_period.split(','),result[0].time_period.split(','))
            //    for (let f = 0; f < timeDiff.length; f++) {
            //         if (timestr !== '') {
            //             timestr += ',' + timeDiff[f]   
            //         }else{
            //             timestr += timeDiff[f]
            //         }
            //    }
               var arr = []
               var promises = []
               var entId = ''
                var cusId = ''
                sql = 
                `SELECT id,customer_id,type,name_of_business,cleaner_pay,supervisor_pay,num_of_supervisor,num_of_cleaner,day_period,time_period,available FROM enterprise WHERE id NOT IN ('${entId}') AND state=? AND country=? AND available=? 
                UNION ALL
                 SELECT id,customer_id,type,customer_name,cleaner_pay,supervisor_pay,num_of_supervisor,num_of_cleaner,day_period,time_period,available FROM subscriptions WHERE customer_id NOT IN ('${cusId}') AND state=? AND country=? AND available=? `;
                conn.query(sql,[req.query.state,req.query.country,'true',req.query.state,req.query.country,'true'], (err,result) => {
                    if (err) {
                        res.send({ success:false });
                        console.log(err,'there was an error inserting link')
                    }else {
                        if (result.length > 0) {
                        promises.push(
                            new Promise(resolve => {
                                for (let i = 0; i < result.length; i++) {
                                    var days = result[i].day_period.split(',')
                                    // var time = result[i].time_period.split(',')
                                    var dayArr = []
                                    for (let d = 0; d < days.length; d++) {
                                        if (dayDiff.includes(days[d])) {
                                            dayArr.push(true)
                                        }else{
                                            dayArr.push(false)
                                        }
                                        if (d + 1 === days.length) {
                                            var newdayArr = dayArr.filter(day => day === true)
                                            var timeArr = []
                                            if (newdayArr.length === days.length) {
                                                arr.push(result[i])
                                                if(i + 1 === result.length){
                                                    resolve(arr)
                                                }
                                                // for (let t = 0; t < time.length; t++) {
                                                //     if (timestr.includes(time[t])) {
                                                //         timeArr.push(true)
                                                //     }else{
                                                //         timeArr.push(false)
                                                //     }
                                                //     if (t + 1 === time.length) {
                                                //         var newtimeArr = timeArr.filter(day => day === true)
                                                //         if (newtimeArr.length === time.length) {
                                                //             arr.push(result[i])
                                                //             if (i + 1 === result.length) {
                                                //                 resolve(arr)
                                                //             }
                                                //         }else if (i + 1 === result.length) {
        
                                                //             resolve(arr)
                                                //         }
                                                //     }
                                                // }
                                            }else if (i + 1 === result.length) {
                                                resolve(arr)
                                            }
                                        }
                                    }
                                }
                            })
                        )
                            Promise.all(promises).then(response => {
                                console.log('response')
                                res.send({ success:true,rows:arr })
                            })
                        }
                    }
                }); 
            }else{
                timestr = req.query.time_period.split(',')
                daystr = req.query.day_period.split(',')
                var businessId = ""
                var customerId = ""
                var arr = []
                for (let d = 0; d < daystr.length; d++) {
                    for (let t = 0; t < timestr.length; t++) {
                        sql = 
                        `SELECT id,customer_id,type,name_of_business,cleaner_pay,supervisor_pay,num_of_supervisor,num_of_cleaner,day_period,time_period,available FROM enterprise WHERE id NOT IN ('${businessId}') AND state=? AND country=? AND available=? AND FIND_IN_SET('${timestr[t]}',time_period) AND FIND_IN_SET('${daystr[d]}',day_period)
                        UNION ALL
                         SELECT id,customer_id,type,customer_name,cleaner_pay,supervisor_pay,num_of_supervisor,num_of_cleaner,day_period,time_period,available FROM subscriptions WHERE id NOT IN ('${customerId}') AND state=? AND country=? AND available=? AND FIND_IN_SET('${timestr[t]}',time_period) AND FIND_IN_SET('${daystr[d]}',day_period)`;
                        conn.query(sql,[req.query.state,req.query.country,'true',req.query.state,req.query.country,'true'], (err,result) => {
                            if (err) {
                                res.send({ success:false });
                                console.log(err,'there was an error inserting link')
                            }else {
                                if (result.length > 0) {
                                    if (businessId.length > 0 && result[0].type !== 'home') {
                                        businessId += ',' + result[0].id
                                    }else if(result[0].type !== 'home'){
                                        businessId += result[0].id
                                    }else if (result[0].type === 'home' && customerId.length > 0) {
                                        customerId += ',' + result[0].id
                                    }else if(result[0].type === 'home'){
                                        customerId += result[0].id
                                    }
                                    arr.push(...result)
                                }
                                if ((d + 1 == daystr.length) && (t + 1 == timestr.length)) {
                                    var homeArr = arr.filter(a => a.type === 'home')
                                    var entArr = arr.filter(a => a.type !== 'home')
                                    var newHomeArr = _.uniq(homeArr, ['id'])
                                    var newEntArr = _.uniq(entArr, ['id'])
                                    res.send({ success:true,rows: [...newEntArr,...newHomeArr],customer:false });
                                }
                            }
                        });
                    }  
                }
            }
        }
    })
});

// Fetch cleaners/supervisor slots filled for enterprise
app.get('/checkCleanerEmployed', (req,res) => {
    if (req.query.type === 'home') {
        var sql = "SELECT id FROM home_cleaners WHERE sub_id=? AND cleaner_id=?";
        conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                sql = "SELECT id FROM home_supervisors WHERE sub_id=? AND supervisor_id=?";
                conn.query(sql,[req.query.sub_id,req.query.cleaner_id], (error,results) => {
                    if (error) {
                        res.send({ success:false })
                        console.log(err)
                    }else {
                        if (results.length > 0 && result.length > 0) {
                            res.send({ success:true,cleanerFilled: true,supervisorFilled:true });   
                        }else if (result.length > 0) {
                            res.send({ success:true,cleanerFilled: true,supervisorFilled:false });  
                        }else if (results.length > 0) {
                            res.send({ success:true,cleanerFilled: false,supervisorFilled:true });  
                        }else{
                            res.send({ success:false,cleanerFilled: false,supervisorFilled:false });
                        }
                    }
                })
            }
        });
    }else{
        var sql = "SELECT id FROM enterprise_cleaners WHERE cleaner_id=? AND enterprise_id=?";
        conn.query(sql,[req.query.cleaner_id,req.query.enterprise_id], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                sql = "SELECT id FROM enterprise_supervisor WHERE enterprise_id=? AND supervisor_id=?";
                conn.query(sql,[req.query.enterprise_id,req.query.cleaner_id], (error,results) => {
                    if (error) {
                        res.send({ success:false })
                        console.log(err)
                    } else {
                        if (results.length > 0 && result.length > 0) {
                            res.send({ success:true,cleanerFilled: true,supervisorFilled:true });   
                        }else if (result.length > 0) {
                            res.send({ success:true,cleanerFilled: true,supervisorFilled:false });  
                        }else if (results.length > 0) {
                            res.send({ success:true,cleanerFilled: false,supervisorFilled:true });  
                        }else{
                            res.send({ success:false,cleanerFilled: false,supervisorFilled:false });
                        }
                    }
                })
            }
        });
    }
});

// count cleaners slots filled up for enterprise
app.get('/checkSlots', (req,res) => {
    if (req.query.type === 'home') {
        var sql = "SELECT COUNT(*) AS cleanerCNT FROM home_cleaners WHERE sub_id=?";
        conn.query(sql,[req.query.enterprise_id], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                sql = "SELECT COUNT(*) AS supervisorCNT FROM home_supervisors WHERE sub_id=?";
                conn.query(sql,[req.query.enterprise_id], (error,results) => {
                    if (error) {
                        res.send({ success:false })
                        console.log(err)
                    } else {
                        console.log(results)
                        res.send({ success:true,cleanerSlotsFilled: result[0].cleanerCNT,supervisorSlotsFilled:results[0].supervisorCNT });
                    }
                })
            }
        });
    }else{
        var sql = "SELECT COUNT(*) AS cleanerCNT FROM enterprise_cleaners WHERE enterprise_id=?";
        conn.query(sql,[req.query.enterprise_id], (err,result) => {
            if (err) {
                res.send({ success:false });
                console.log(err,'there was an error inserting link')
            }else {
                sql = "SELECT COUNT(*) AS supervisorCNT FROM enterprise_supervisor WHERE enterprise_id=?";
                conn.query(sql,[req.query.enterprise_id], (error,results) => {
                    if (error) {
                        res.send({ success:false })
                        console.log(err)
                    } else {
                        console.log(results)
                        res.send({ success:true,cleanerSlotsFilled: result[0].cleanerCNT,supervisorSlotsFilled:results[0].supervisorCNT });
                    }
                })
            }
        });
    }
});

// Fetch ongoing completed jobs
app.get('/fetchActiveCompletedJobs', (req,res) => {
    var sql = "SELECT * FROM job_completion WHERE sub_id=? AND place=? AND timestamp > ? AND timestamp < ?";
    conn.query(sql,[req.query.sub_id,req.query.letters,req.query.startOfDaytime,req.query.time], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            if (result.length > 0) {
                res.send({ success:true,rows: result });   
            }else{
                res.send({ success:false,rows: result });
            }
        }
    });
});

// Fetch cleaner work Period
app.get('/fetchCleanerWorkTime', (req,res) => {
    var sql = "SELECT * FROM work_period WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,row: result[0] });
        }
    });
});

// Fetch cleaner work Period
app.get('/fetchCleanerlevel', (req,res) => {
    var sql = "SELECT level,rating FROM cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,row: result[0] });
        }
    });
});

// Fetch cleaner enterprise jobs as cleaner
app.get('/fetchCleanerJobs', (req,res) => {
    var sql = "SELECT * FROM enterprise_cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,rows: result });
        }
    });
});

// Fetch all cleaner jobs including homes
app.get('/fetchAllCleanerJobs', (req,res) => {
    var arr = []
    var sql = "SELECT enterprise_id FROM enterprise_cleaners WHERE cleaner_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            var enterprise_info = []
            var home_info = []
            sql = "SELECT enterprise_id FROM enterprise_supervisor WHERE supervisor_id=?";
            conn.query(sql, [req.query.cleanerId], (err, results) => {
                arr.push(...result, ...results)
                const uniq = new Set(arr.map(e => JSON.stringify(e)));
                const newArr = Array.from(uniq).map(e => JSON.parse(e));
                if (err) {
                    console.log(err,'err')
                    res.send({ success:false })
                }else{
                    for (let i = 0; i < newArr.length; i++) {
                        sql = "SELECT * FROM enterprise WHERE id=?";
                        conn.query(sql, [newArr[i].enterprise_id], (err, result) => {
                            if (err) {
                                console.log(err,'there was error')
                            }else{
                                enterprise_info.push(...result)
                            }
                        })
                    }
                    var subId = []
                    sql = "SELECT sub_id FROM home_cleaners WHERE cleaner_id=?"
                    conn.query(sql, [req.query.cleanerId], (err, result) => {
                        if (err) {
                            console.log(err)
                            res.send({ success:false })
                        }else{
                            if (result.length > 0) {
                                subId.push(...result)   
                            }
                            console.log(subId)
                            sql = "SELECT sub_id FROM home_supervisors WHERE supervisor_id=?"
                            conn.query(sql, [req.query.cleanerId], (err, result) => {
                                if (err) {
                                    console.log(err)
                                    res.send({ success:false })
                                }else{
                                    if (result.length > 0) {
                                        subId.push(...result)   
                                    }
                                    if (subId.length > 0) {
                                        for (let h = 0; h < subId.length; h++) {
                                            sql = "SELECT * FROM subscriptions WHERE id=?"
                                            conn.query(sql, [subId[h].sub_id], (err, result) => {
                                                if (err) {
                                                    console.log(err)
                                                }else{
                                                    home_info.push(...result)
                                                    if (subId.length === h + 1) {
                                                        res.send({ success:true,customer:home_info,enterprise:enterprise_info })
                                                    }
                                                }
                                            })
                                        }
                                    }else{
                                        res.send({ success:true,customer:home_info,enterprise:enterprise_info })
                                    }
                                }
                            })
                        }
                    })
                }
            })
        }
    });
});

// Fetch cleaner work Period
app.get('/fetchSupervisorJobs', (req,res) => {
    var sql = "SELECT * FROM enterprise_supervisor WHERE supervisor_id=?";
    conn.query(sql,[req.query.cleanerId], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,rows: result });
        }
    });
});

// Fetch supervisors from enterprise
app.get('/fetchSupervisors', (req,res) => {
    var sql = "SELECT * FROM enterprise_supervisor WHERE enterprise_id=?";
    conn.query(sql,[req.query.enterprise_id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,rows: result });
        }
    });
});

// Fetch cleaners from enterprise
app.get('/fetchCleaners', (req,res) => {
    var sql = "SELECT * FROM enterprise_cleaners WHERE enterprise_id=?";
    conn.query(sql,[req.query.enterprise_id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,rows: result });
        }
    });
});

// Fetch Enterpise Info
app.get('/getEnterpriseInfo', (req,res) => {
    var sql = "SELECT * FROM enterprise WHERE id=?";
    conn.query(sql,[req.query.id], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,row: result });
        }
    });
});

// Add enterprise
app.get('/addEnterprise', (req,res) => {
    var sql = "INSERT INTO enterprise(name_of_business,cac_number,num_of_cleaner,num_of_supervisor,type,time_period,skill_level,monthly_payment,monthly_cleaner_payment,extras,state,country,location,latitude,longitude,available) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    conn.query(sql,[req.query.name,req.query.cac,req.query.cleanersNumber,req.query.supervisor,req.query.type,req.query.time,req.query.cleanerLevel,req.query.monthlyPay,req.query.cleanerPay,req.query.extras,req.query.state,req.query.country,req.query.location,req.query.latitude,req.query.longitude,'true'], (err,result) => {
        if (err) {
            res.send({ success:false });
            console.log(err,'there was an error inserting link')
        }else {
            res.send({ success:true,rows:result.insertId }); // <---    
        }
    });
});
// Check if user has an order
// app.get('/verifyUser', async(req,res) => {
//     const salt = await bcrypt.genSalt()
//     bcrypt.hash(req.query.password, salt).then(hashedPwd => {
//         var sql = "SELECT password FROM usersinfo WHERE email=?";
//         conn.query(sql,[req.query.email], (err,result,fields) => {
//             if (err) {
//                 res.send({ success:false });
//                 console.log(err, 'there was an error getting cleaner')
//             }else {
//                 if (hashedPwd === result[0].password) {
//                     res.send({ success:true });   
//                 }else{
//                     res.send({ success:false });
//                 }
//             }
//         });
//     });
// });