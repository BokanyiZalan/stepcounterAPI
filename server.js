require('dotenv').config()
const express =require('express')
const mysql = require('mysql')
const sha1 = require('sha1')
var cors= require('cors')
const app = express()
const port = process.env.APP_PORT
const pwdRegExp=/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/


var pool = mysql.createPool({
  connectionLimit:      process.env.DB_CONN_LIMIT,
  multipleStatements:   process.env.DB_MULTI_QUERY,
  host:                 process.env.DB_HOST,
  user:                 process.env.DB_USER,
  password:             process.env.DB_PASS,
  port:                 process.env.DB_PORT,
  database:             process.env.DB_NAME,
  timezone:             process.env.DB_TIMEZONE


})
app.use(cors())
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.get('/', (_req, res) => {
  res.send('Welcome to the step counter API')
})

//users endpoint


//registration
app.post('/users/register', (req, res) => {
    const {name, password, email, confirm} = req.body
    console.log(name, password, email, confirm)
    //validate input
    if(!name || !password || !email || !confirm) {
      return res.status(400).json({ error: 'All fields are required' })
    }
    if(password !== confirm) {
      return res.status(400).json({ error: 'Passwords do not match' })
    }
    
    // implement password strength check
    if(!password.match(pwdRegExp)){
      return res.status(400).json({ error: 'The new password is too weak' })
    }



    //check if email already exists
    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal server error' })
        }
        if (results.length > 0) {
            return res.status(400).json({ error: 'Email already exists' })
        }
        //register user
        pool.query('INSERT INTO users (name, password, email, role) VALUES (?, SHA1(?), ? ,"user")', [name, password, email], (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Internal server error' })
            }
            res.status(201).json({ message: 'User registered successfully' })
        })
    })

})

//login
app.post('/users/login', (req, res) => {
    const { email, password } = req.body
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' })
    }
    pool.query('SELECT * FROM users WHERE email = ? AND password =SHA1(?)', [email, password], (error, results) => {
      console.log(results)  
      if (error) {
            return res.status(500).json({ error: 'Internal server error' })
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'Invalid credentials' })
        }
        //check user is active?
        if (results[0].is_active == 0) {
            return res.status(400).json({ error: 'User is not active' })
        }
        // update last login and login_count fields timestamp
        const loggedUser={
            ID: results[0].ID,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        }
        pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE ID = ?', [loggedUser.ID], (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Internal server error' })
            }
            // send logged in data to frontend
            res.status(200).json({ message: 'Login successful', loggedUser})
        })
    })
})

//logout ? nem kell backend endpoint

//password change
app.post('/users/:uid/passmod', (req, res) => {
  const { oldpass,newpass,confirm } = req.body
  const uid=req.params.uid
  if (!oldpass || !newpass || !confirm) {
    return res.status(400).json({ error: 'All fields are required' })
  }
  if (newpass != confirm) {
    return res.status(400).json({ error: 'Passwords do not match' })
  }
  if (newpass == oldpass) {
    return res.status(400).json({ error: 'New password must be different from old password' })
  }
  // new password strength check
if(!newpass.match(pwdRegExp)){
      return res.status(400).json({ error: 'The new password is too weak' })
    }

  pool.query('SELECT password FROM users WHERE ID=?', [uid], (error, results) => {
    console.log(results)
    if (error) {
      return res.status(500).json({ error });
    }
    
    if (results.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const oldpassHash = sha1(oldpass);
    
    console.log(oldpassHash);
    
    if (results[0].password != oldpassHash) {
      return res.status(400).json({ error: 'Old password is incorrect' });
    }
    
    // update password
    pool.query('UPDATE users SET password=SHA1(?) WHERE ID=?', [newpass, uid], (error, results) => {
      if (error) {
        return res.status(500).json({ error: 'Database query error' });
      }
      
      
      return res.status(200).json({ message: 'Password changed successfully' });
    });
  });
})


//get profile
app.get('/users/:uid', (req, res) => {
  const uid=req.params.uid
  if (!uid) {
    return res.status(400).json({ error: 'User ID is required' })
  }
  pool.query('SELECT * FROM users WHERE ID = ?', [uid], (error, results) => {
    if (error) {
      return res.status(500).json({ error: 'Database query error' })
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' })
    }

    let user={ 
    "name": results[0].name,
    "email": results[0].email,
    "role": results[0].role,
    "created_at": results[0].created_at
    
    
   
    }
    // return user profile data
    res.status(200).json({ results: user })
  })
})

//update profile(name,email)
app.patch('/users/:uid', (req, res)=>{
    const uid=req.params.uid
    const {username, email, luid}=req.body

    if(!uid||!username||!email||!luid){
      return res.status(400).json({error: "Missing req fields."})
    }
    
    if(uid!=luid){
      return res.status(400).json({error: "Not your account."})
    }

    pool.query('SELECT * FROM users WHERE ID=?',[uid], (error, results) => {
      if(error){
        return res.status(500).json({error: 'Database query error.'})
      }
      if (results.length === 0) {
      return res.status(400).json({ error: 'User not found' })
    }
    if((username==results[0].name)&&(email==results[0].email)){
      return res.status(200).json({ message: 'No update occured' });
    }
    pool.query('SELECT * FROM users WHERE email=? AND ID<>?',[email,uid],(error,results2)=>{
      if(error){
        return res.status(500).json({error: 'Database query error.'})
      }
      if(results2.length>0){
        return res.status(400).json({ error: 'email already used.' })
      }
      pool.query('UPDATE users SET name=?,email=?, updated_at=CURRENT_TIMESTAMP WHERE ID=?',[username,email,uid],(error,results)=> {
        if (error){
           return res.status(500).json({error: 'Database query error.'})
        }
        return res.status(200).json({ message: 'User updated succesfully' });
      })
    })
  })
})


//delete profile
app.delete('/users/:uid', (req, res) => {

  const uid=req.params.uid
  const loggedUserId=req.body.luid
  if (!uid || !loggedUserId) {
    return res.status(400).json({ error: 'User ID and logged-in user ID are required' })
  }
  if (uid != loggedUserId) {
    return res.status(400).json({ error: 'You dont have permission to delete this user.' })
  }

  pool.query('DELETE FROM users WHERE ID = ?', [uid], (error, results) => {
    if (error) {
      return res.status(500).json({ error: 'Database query error' })
    }
   if (results.affectedRows === 1) {
      return res.status(200).json({ message: 'User deleted successfully' })
    }
    return res.status(200).json({ message: 'No delete action performed' })
  })
})





//steps endpoint


//create step
app.post('/steps',(req,res)=>{
    const luid = req.body.luid
    const {step_count, date} = req.body
    let today = new Date()
 
    if(!luid || !step_count || !date){
        return res.status(400).json({ message: 'All fields are required' });
    }
    if(step_count<0){
        return res.status(400).json({message: 'steps cant be nagative'})
    }
    if(new Date(date)>today){
        return res.status(400).json({message: 'cant registed steps for the future'})
    }
    pool.query('SELECT * FROM users WHERE ID=?',[luid],(error,result1)=>{
        if (error){
            return res.status(500).json({ error: 'Database query error', error });
        }
        if (result1.length == 0) {
            return res.status(400).json({ message: 'this user doesnt exist' });
        }
        pool.query('SELECT * FROM steps WHERE user_id=? AND date=?',[luid,date], (error,result2)=>{
        if (error){
            return res.status(500).json({ message: 'Database query error', error });
        }
        if (result2.length > 0) {
            return res.status(400).json({ message: 'you have already registered a step count for this date' });
        }
        pool.query('INSERT INTO steps (user_id,step_count,date) VALUES (?, ?, ?)', [luid, step_count, date], (error, results3) => {
            if(error) {
                return res.status(500).json({ message: 'Database error', error });
            }
            return res.status(200).json({ message: 'Step registered successfully' });
        });    
    })
    })
})
   
    
    
  



//get step
app.get('/steps/:uid',(req,res)=>{
    const uid = req.params.uid
 
    if(!uid){
        return res.status(400).json({error: 'missing user identifier'})
    }
 
    pool.query('SELECT * FROM steps WHERE user_id=? ' , [uid], (error, result) =>{
        if (error) {
            return res.status(500).json({ error: 'Database query error', });
        }
        if (result.length == 0){
            return res.status(400).json({error: 'You dont have registerd steps'})
        }
        return res.status(200).json(result)
    })
 
})
 
// steps update
app.patch('/steps/:stepID',(req,res)=>{
    const stepID = req.params.stepID
    const {step_count} = req.body
 
    if (!step_count ){
        return res.status(400).json({ error: "missing required fields"})
    }
    if(step_count<0){
        return res.status(400).json({message: 'steps cant be nagative'})
    }
    pool.query('SELECT * FROM steps WHERE ID=?',[stepID],(error,results)=>{
        if(error){
            return res.status(500).json({ error: 'Database update error', });
        }
        if (results.length ==0){
            return res.status(400).json({error: 'this step doesnt exist'})
        }
        pool.query("update steps set step_count=?, updated_at=CURRENT_TIMESTAMP where ID=?", [step_count,stepID], (error,results3)=>{
            if(error){
                return res.status(500).json({ error: 'Database update error', });
            }
            return res.status(200).json({message:' step upodated succesfuly'})
        })
 
    })
})
 
// delete step
app.delete('/steps/:stepID', (req, res) => {

    const stepID = req.params.stepID
    const luid = req.body.luid

    if (!stepID) {
        return res.status(400).json({
            error: 'missing step identifier'
        })
    }

    if (!luid) {
        return res.status(400).json({
            error: 'missing user identification'
        })
    }

    pool.query(
        'DELETE FROM steps WHERE ID=? AND user_id=?',
        [stepID, luid],
        (error, results) => {

            if (error) {
                console.log(error)

                return res.status(500).json({
                    error: 'database query error'
                })
            }

            if (results.affectedRows === 1) {
                return res.status(200).json({
                    message: 'step deleted successfully'
                })
            }

            return res.status(404).json({
                error: 'step not found or does not belong to this user'
            })
        }
    )
})

/* }) */

//admin endpoint


//get all users
app.post('/admin/users', (req, res) => {
  const luid=req.body.luid
  if(!luid){
     return res.status(400).json({ error: 'Missing required fields' })
  }
  pool.query('SELECT * FROM users WHERE ID=?', [luid],(error, results1) => {
    if (error) {
      return res.status(500).json({ error })
    }
   if(results1.length==0){
     return res.status(400).json({ error: 'User with this id doesnt exist.' })
  
   }
    if(results1[0].role!='admin'){
     return res.status(400).json({ error: 'You dont have premission.' })
  
   }
   pool.query('SELECT * FROM users ',(error, results) => {
      if (error){
        return res.status(500).json({ error: 'Database query error' })
      }
      return res.status(200).json({ results})
   })
   
  })
})

//deny user
app.patch('/deny/:id', (req, res) => {
    const luid = req.body.luid;
    const id = req.params.id;
    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!id) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('UPDATE users SET role = ? WHERE ID = ?', ['denied', id], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'User denied successfully' });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
        })
    })
})

//statistics
app.post('/admin/statistics',(req,res)=>{
  const luid=req.body.luid
  if(!luid){
    return res.status(400).json({ error: 'Cant get others users steps.' })
  }
  pool.query('SELECT * FROM users WHERE ID=?',[luid] ,(error,results)=>{
    if (error){
      return res.status(500).json({ error: 'Database query error' })
    }
    if(results.length==0){
      return res.status(400).json({ error: 'user with this id doesnt exist' })
    }
    if(results[0].role != 'admin'){
        return res.status(403).json({ error: 'you dont have premission' })
    }
    pool.query(
      `SELECT 
      COALESCE(SUM(step_count), 0) AS total, 
      COALESCE(AVG(step_count), 0) AS avg 
      FROM steps ;
        SELECT 
          users.name,
          users.email,
          COALESCE(SUM(steps.step_count),0) AS steps
        FROM users
        INNER JOIN steps ON users.ID = steps.user_id
        GROUP BY users.ID, users.name, users.email
        ORDER BY steps DESC
        LIMIT 0,3
       `,(error,results) => {
            if (error){
              return res.status(500).json({ error: 'Database query error' })
              }
              console.log(results)
              return res.status(200).json(results )

       })
  })
})
//admin endpoints

//get users
app.get('/users', (req, res) => {
  const luid=req.body.luid
  if(!luid){
     return res.status(400).json({ error: 'Missing required fields' })
  }
  pool.query('SELECT * FROM users WHERE ID=?', [luid],(error, results) => {
    if (error) {
      return res.status(500).json({ error })
    }
    if(results.length==0){
     return res.status(400).json({ error: 'User with this id doesnt exist.' })
    }
    if(results.length>0 && results[0].role!='admin'){
     return res.status(400).json({ error: 'You dont have premission.' })
    }
    pool.query('SELECT * FROM users ',(error, results) => {
      if (error){
        return res.status(500).json({ error: 'Database query error' })
      }
      return res.status(200).json({ results})
   })
  })
})
//post weather
app.post('/weather', (req, res) => {
    const luid = req.body.luid;
    const { date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index } = req.body;
    if (!luid || !date || !location || !temp_min || !temp_max || !weather_type || !precipitation || !precipitation_probability || !wind_speed || !wind_direction || !humidity || !pressure || !uv_index){
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (temp_min > temp_max) {
        return res.status(400).json({ error: 'Minimum temperature cannot be greater than maximum temperature' });
    }
    if (precipitation_probability < 0 || precipitation_probability > 100) {
        return res.status(400).json({ error: 'Precipitation probability must be between 0 and 100' });
    }
    if (uv_index < 0 || uv_index > 11) {
        return res.status(400).json({ error: 'UV index must be between 0 and 11' });
    }
    if (humidity < 0 || humidity > 100) {
        return res.status(400).json({ error: 'Humidity must be between 0 and 100' });
    }
    if (pressure < 0) {
        return res.status(400).json({ error: 'Pressure must be greater than 0' });
    }
    if (wind_speed < 0) {
        return res.status(400).json({ error: 'Wind speed must be greater than 0' });
    }
    if (precipitation < 0) {
        return res.status(400).json({ error: 'Precipitation must be greater than 0' });
    }
pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('INSERT INTO weather (date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(201).json({ message: 'Weather data added successfully' });
            }
        })
    })
})
//patch weather
app.patch('/weather', (req, res) => {
    const luid = req.body.luid;
    const { date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index } = req.body;
    if (!luid || !date || !location || !temp_min || !temp_max || !weather_type || !precipitation || !precipitation_probability || !wind_speed || !wind_direction || !humidity || !pressure || !uv_index){
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (temp_min > temp_max) {
        return res.status(400).json({ error: 'Minimum temperature cannot be greater than maximum temperature' });
    }
    if (precipitation_probability < 0 || precipitation_probability > 100) {
        return res.status(400).json({ error: 'Precipitation probability must be between 0 and 100' });
    }
    if (uv_index < 0 || uv_index > 11) {
        return res.status(400).json({ error: 'UV index must be between 0 and 11' });
    }
    if (humidity < 0 || humidity > 100) {
        return res.status(400).json({ error: 'Humidity must be between 0 and 100' });
    }
    if (pressure < 0) {
        return res.status(400).json({ error: 'Pressure must be greater than 0' });
    }
    if (wind_speed < 0) {
        return res.status(400).json({ error: 'Wind speed must be greater than 0' });
    }
    if (precipitation < 0) {
        return res.status(400).json({ error: 'Precipitation must be greater than 0' });
    }
  pool.query('UPDATE weather SET date = ?, location = ?, temp_min = ?, temp_max = ?, weather_type = ?, precipitation = ?, precipitation_probability = ?, wind_speed = ?, wind_direction = ?, humidity = ?, pressure = ?, uv_index = ? WHERE ID = ?', [date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index, id], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'Weather data updated successfully' });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'Weather data not found' });
            }
        })
    })
//delete weather

app.delete('/weather/:id', (req, res) => {
    const luid = req.body.luid;
    const id = req.params.id;
    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!id) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
pool.query('DELETE FROM weather WHERE ID = ?', [id], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'Weather data deleted successfully' });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'Weather data not found' });
            }
        })
    })
})

//get weather
app.get('/weather', (req, res) => {
    pool.query('SELECT * FROM weather', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'No weather data found' });
        }
        if (results.length > 0) {
            return res.status(200).json({results});
        }
    })
})

//get weather details
app.get('/weather/:id', (req, res) => {
    const id = req.params.id;
    pool.query('SELECT * FROM weather WHERE ID = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Weather data not found' });
        }
        if (results.length > 0) {
            return res.status(200).json({results});
        }
    })
})
app.patch('/deny/:id', (req, res) => {
    const luid = req.body.luid;
    const id = req.params.id;
    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!id) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('UPDATE users SET role = ? WHERE ID = ?', ['denied', id], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'User denied successfully' });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
        })
    })
})
  

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`)
})