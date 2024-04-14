/** User class for message.ly */

const db=require('../db')
const bcrypt=require('bcrypt')
const ExpressError = require("../expressError")
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {
constructor({username,password,first_name,last_name,phone,join_at,last_login_at}){
  this.username=username
  this.password=password
  this.first_name=first_name
  this.last_name=last_name
  this.phone=phone
  this.join_at=join_at
  this.last_login_at=last_login_at
}
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    const hashed_pw= await bcrypt.hash(password,BCRYPT_WORK_FACTOR)
    const result = await db.query(`insert into users (username,password,first_name,last_name,phone,join_at,last_login_at) values 
                    ($1,$2,$3,$4,$5,current_timestamp,current_timestamp) 
                    returning username,password,first_name,last_name,phone`,
                    [username,hashed_pw,first_name,last_name,phone])
                    return result.rows[0]
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(`select username, password from users where username=$1`,[username])
    let user = result.rows[0]
    if(user){
      if(await bcrypt.compare(password,user.password)){
        return user
      }
    }else{
      throw new ExpressError("Invalid username/password",400)
    }
   }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`update users set last_login_at= current_timestamp where username=$1 returning username`,[username])
    if(!result.rows[0]){
      throw new ExpressError("No username found",404)
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(`select username,first_name,last_name,phone from users`)
    return results.rows
   }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`select username,first_name,last_name,phone,join_at,last_login_at from users where username=$1`,[username])
    if(!result.rows[0]){
      throw new ExpressError("No username found",404)
    }
    return result.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const results= await db.query(`select m.id,m.to_username,m.body,m.sent_at,m.read_at,u.first_name,u.last_name,u.phone from messages as m 
                    join users as u on u.username= m.to_username where from_username=$1`,[username])

    const messages= results.rows
    return messages.map(m => ({id: m.id,to_user: {username: m.to_username,first_name: m.first_name,last_name: m.last_name,
            phone: m.phone},body: m.body,sent_at: m.sent_at,read_at: m.read_at}));
    

  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const result = await db.query( `SELECT m.id,m.from_username, u.first_name,u.last_name,u.phone,m.body, m.sent_at,m.read_at
                  FROM messages AS m JOIN users AS u ON m.from_username = u.username WHERE to_username = $1`,[username]);

  return result.rows.map(m => ({id: m.id,from_user: {username: m.from_username, first_name: m.first_name,last_name: m.last_name,
      phone: m.phone,},body: m.body,sent_at: m.sent_at,read_at: m.read_at}));
}
}


module.exports = User;