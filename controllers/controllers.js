let {initDB}=require('../dbConfig')
let jwt = require('jsonwebtoken')
var CryptoJS = require("crypto-js");
const bcrypt = require('bcrypt')
const salt = '$2b$10$6UJPA6UZBC6UZBC6UJPA6U';

let userCollection;
async function userColl(){
    userCollection=await initDB()
}

userColl()

let signup=async (req,res)=>{

    //fetching data from body
    let {email,phNum,fName,password}=req.body;
    console.log(email,phNum,fName,password);

    
    //hash password for security reason
    const hashedPassword = await bcrypt.hash(password, salt)

    console.log("hashedPassword",hashedPassword);

    // Encrypt email,phNum and first name
    var encEmail = CryptoJS.AES.encrypt(email, 'secret key 123').toString();
    var encPhNum = CryptoJS.AES.encrypt(phNum, 'secret key 123').toString();
    var encFName = CryptoJS.AES.encrypt(fName, 'secret key 123').toString();

    try {
        //insert email,name ,password and phone number in database
        let newUser = await userCollection.insertOne({ 'name': encFName, 'email': encEmail, 'password': hashedPassword,'number':encPhNum})
        res.send("SignUp successful!!")
    } catch (error) {
        
        console.log("Error in SignUp",error)
        res.send("Error in SignUp")
    }

}

let login=async (req,res)=>{
    //get data from request body
    let{email,password}=req.body;
    
    console.log("line 47",email,password);

    //hash password
    let passAsCondition = await bcrypt.hash(password, salt)

    //getting user data from db
    let credentials=await userCollection.findOne({'password':passAsCondition})

    console.log("credential, line 55",credentials)

    //checking for invalid credentials
    // if(credentials){
        //res.send("Invalid Credentials!")
    

        //Decrypt email
        var bytes  = CryptoJS.AES.decrypt(credentials.email, 'secret key 123');
        var decryptedData = bytes.toString(CryptoJS.enc.Utf8);
        console.log("line 65,decryptedData",decryptedData)
        //checking for email 
        if(decryptedData===email){
            

            //generating userId using Math.random()
            const userId = Math.floor(Math.random() * 100) + 1;

            //add email,userId,phNum in userPAyload for cookie
            let userPayload = { email:decryptedData, password:credentials.password,userId:userId,phNum:credentials.number };
            
            console.log("userPayload,line 60",userPayload);

            //adding userId generated in collection of the user
            let result= await userCollection.updateOne({"password":credentials.password},{$set:{'userId':userId}});

           
            let token = jwt.sign(userPayload,'jwtKey', { expiresIn: '1d' })
            // console.log(token);
            res.cookie('jwt', token);

            res.send("login successfull!")


        }
        // else{
        //     res.send("Invalid credentials")
        // }

       
    }

    
//}

let logout = (req, res) => {
    res.cookie('jwt', '')
    res.send("Log out successfull!")
    
    console.log('logout');
}

let user=async(req,res)=>{

    let token = req.cookies.jwt
        if(token){
        let userdata = jwt.verify(token,'jwtKey')
        let { email, password } = userdata;
        console.log(email,password);

        var bytes  = CryptoJS.AES.decrypt(userdata.email, 'secret key 123');
        var decryptedEmail = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

        

        try {
            
            let asCondition=CryptoJS.AES.encrypt(decryptedEmail, 'secret key 123').toString();
            let userInfo=await userCollection.find({"email":asCondition})
            if(!userInfo){
                res.send("Email Id invalid, Please signup and then try to login")
            }
            else{


                // Decrypt

                let bytes;
                  bytes  = CryptoJS.AES.decrypt(userInfo.name, 'secret key 123');
                 var decryptedName = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

                  bytes  = CryptoJS.AES.decrypt(userInfo.number, 'secret key 123');
                 var decryptedNumber = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

                  bytes  = CryptoJS.AES.decrypt(userInfo.email, 'secret key 123');
                 var decryptedEmail = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

                 let userObj={
                    "Full Name":decryptedName,
                    "Email":decryptedEmail,
                    "Phone Number":decryptedNumber
                 }

                 res.send(userObj)

            }

        } catch (error) {

            console.log("Error fetching userData");
        }
        


        res.send("user data fetched successfully!!",email,password)
        }

}


let resetPass=async (req,res)=>{

    //fetch data from body
    let {oldPassword,newPassword}=req.body;
    console.log(oldPassword,newPassword);

    //checking for invalid inputs
    if(oldPassword==undefined){
        if(newPassword==undefined){
            res.send("Invalid input,please enter oldPassword and newPassword ro reset")
        }
    }

    //checking for invalid inputs
    if(oldPassword==undefined||newPassword==undefined){
        res.send("Password missing ,please enter valid input")
    }

    //retriving userId from cookie
    let token = req.cookies.jwt
    console.log("token",token);
        if(token){
        let userdata = jwt.verify(token,'jwtKey')
        let { email,userId} = userdata;

        console.log("line 166",email,userId);

        //hash oldPassword 
        let hashOldPassword = await bcrypt.hash(oldPassword, salt)
        console.log("hashOldPassword",hashOldPassword,"password","ln 169");
        

        //get user data from db
            let userData=await userCollection.findOne({"userId":userId})
            console.log(userData,"line 193,userData");
        
        //checking for same password
        if(userData.password===hashOldPassword){

            console.log("line 196 ,password is matched");

            //hash new password
            let hashNewPassword=await bcrypt.hash(newPassword, salt)

            console.log(hashNewPassword,"line 200");

            //update password
            let result= await userCollection.updateOne({userId},{$set:{'password':hashNewPassword}});
            console.log(result,"ln 198,result");


            res.send("Password reset successfull!!")
        }

        else{
            console.log("invalid password");
            res.send("Invalid password")
            }
    }
    else{
        res.send("Error login")
    }
        
}


let editUser=async(req,res)=>{

    //fetching data from body 
    let {fname,phNum,email}=req.body;

    //checking for invalid input
    if(fname==undefined){
        if(phNum==undefined){
            if(email==undefined){
                res.send("Invalid Input,please add a valid input")
            }
            
        }
    }
    
    //retriving userId from cookie
    let token = req.cookies.jwt
    if(token){
    let userdata = jwt.verify(token,'jwtKey')
    let { userId } = userdata;
    
    //update name  

    if(fname!=undefined){
        
        var encFName = CryptoJS.AES.encrypt(fname, 'secret key 123').toString();
        console.log("encFName line 281",encFName);
        let result= await userCollection.updateOne({"userId":userId},{$set:{'name':encFName}});
        console.log("line 283",result);


        }

        //update phone number

    if(phNum!=undefined){
        
        var encPhNum = CryptoJS.AES.encrypt(phNum, 'secret key 123').toString();
        console.log("encPhNum line 291",encPhNum);
        let result= await userCollection.updateOne({"userId":userId},{$set:{'number':encPhNum}});

            }

        //update email

    if(email!=undefined){

        var encEmail = CryptoJS.AES.encrypt(email, 'secret key 123').toString();
        console.log("encEmail line 300",encEmail);
        let result= await userCollection.updateOne({"userId":userId},{$set:{'email':encEmail}});
    
            }
            res.send("User details updated successfull!")
    }

}


//export modules to app.js
module.exports={
    signup,
    login,
    user,
    logout,
    resetPass,
    editUser
}




// var CryptoJS = require("crypto-js");

// var data = [{id: 1}, {id: 2}]

// // Encrypt
// var ciphertext = CryptoJS.AES.encrypt(JSON.stringify(data), 'secret key 123').toString();

// // Decrypt
// var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
// var decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

// console.log(decryptedData); // [{id: 1}, {id: 2}]




// var CryptoJS = require("crypto-js");

// // Encrypt
// var ciphertext = CryptoJS.AES.encrypt('Veeresh FSD', 'secret key 123').toString();

// // Decrypt
// var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
// var originalText = bytes.toString(CryptoJS.enc.Utf8);

// console.log(originalText); // 'my message'

































// //FINAL BCRYPT HASHING EQUAL

// const bcrypt = require('bcrypt');

// // This is the old hashed password that was stored in the database
// const oldHashedPassword = '$2b$10$6UJPA6UZBC6UZBC6UJPA6UZBC6UZBC6UJPA6UZBC6UZBC6UJPA6U';

// // This is the new password that needs to be checked
// const newPassword = 'myNewPassword';

// // This is the salt that was used to hash the old password
//  const salt = '$2b$10$6UJPA6UZBC6UZBC6UJPA6U';


// // Hash the new password using the same salt
// const newHashedPassword = bcrypt.hashSync(newPassword, salt);
// const AnewHashedPassword = bcrypt.hashSync(newPassword, salt);

// // Compare the two hashed passwords
// if (newHashedPassword === AnewHashedPassword) {
//   console.log('Password matches');
// } else {
//   console.log('Password does not match');
// }
