const express = require('express');
const axios = require('axios');
const app = express();
const {Datastore} = require('@google-cloud/datastore');

const bodyParser = require('body-parser');
const request = require('request');

const datastore = new Datastore();

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const jwtDecode = require('jwt-decode');
const { auth } = require('express-openid-connect');
const validator = require('validator');

const CAT = "cats";

const router = express.Router();


const CLIENT_ID = 'VYh5oeO91ANZuiWpcQQZjT8xWFSiHFln';
const CLIENT_SECRET = 'VVMEZauuX3CeLKj36vjIsdGyKJNrnOE2qMS9c4QAfuap0iuXrOFnFb2rTfVbnKag';
const DOMAIN = 'week7auth0.us.auth0.com';


const config = {
    authRequired: false,
    auth0Logout: true,
    baseURL: 'https://finalproject-407803.uw.r.appspot.com',
    clientID: `${CLIENT_ID}`,
    issuerBaseURL: `https://${DOMAIN}`,
    secret: `${CLIENT_SECRET}`,
    clientSecret: `${CLIENT_SECRET}`,
    authorizationParams: {
      response_type: 'code',
      audience: 'https://week7auth0.us.auth0.com/api/v2/',
      scope: 'openid profile email offline_access read:users',
      state: true,
    },
  };
app.use(auth(config));


  app.get('/', (req, res) => {
    if (req.oidc.isAuthenticated()) {
      const accessToken = req.oidc.accessToken;
      const decoded = jwtDecode.jwtDecode(JSON.stringify(accessToken));
  
      res.send(`<h1>Logged in</h1> <p>JWT: ${JSON.stringify(accessToken)}</p> <br> <p>Decoded: ${JSON.stringify(decoded)}</p>`);
    } else {
      res.send('Logged out');
    }
  });


app.use(bodyParser.urlencoded({ extended: true }));



app.use(bodyParser.json());


function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
  });

/* ------------- Begin Cat Model Functions ------------- */

function onlyLettersAndSpaces(str){
    return /^[a-zA-Z\s]+$/.test(str);
}


async function post_cat(name, type, weight, eyeColor, owner, req) {
    if(!onlyLettersAndSpaces(name)|| !validator.isLength(name, {min:1, max: 26})
        || !validator.isLength(type, {min:1, max: 26}) || !onlyLettersAndSpaces(type)
        || !Number.isInteger(weight) || weight < 1 || weight > 50 || !onlyLettersAndSpaces(eyeColor)|| !validator.isLength(eyeColor, {min:1, max: 26})){
        return {"data": "invalid"}
    }
    const cat_name = datastore.createQuery("cats").filter("name", "=", name);
    const name_results = await datastore.runQuery(cat_name);
    if(name_results[0].length > 0){
        return {"data": "name"}
    }
    const key = datastore.key(CAT);
    const new_cat = {"name": name, "type": type, "weight": weight, "eyeColor": eyeColor, "owner": owner, "preys": [], self: null};
    await datastore.save({"key":key, "data":new_cat});
    await self_cat(key.id, req)
    return key;
}

async function self_cat(id, req){
    const cat = datastore.key([CAT, parseInt(id,10)]);
    const mycat = await datastore.get(cat);
    if(mycat[0] == undefined || mycat[0] == null){
        return {"data":false}
        }
    mycat[0].self = req.protocol + "://" + req.get('host') + req.baseUrl + "/cats/" + id
    await datastore.update(mycat[0])
    return true
}

// needs pagination
async function get_cats(owner, limit = 5, offset = 0) {
    const q = datastore.createQuery(CAT).filter('owner', '=', owner).limit(limit).offset(offset);    
    const entities = await datastore.runQuery(q);
    const cats = entities[0].map(fromDatastore);
    var cats2 = [];
    var preylist = [];
  
    for (var i = 0; i < cats.length; i++) {
      if (cats[i].owner == owner) {
        for (var j = 0; j < cats[i].preys.length; j++) {
          const prey = datastore.key(["prey", parseInt(cats[i].preys[j].id, 10)]);
          const myprey = await datastore.get(prey);
          preylist.push({
            id: cats[i].preys[j].id,
            self: myprey[0].self,
            animal: myprey[0].animal,
          });
        }
        cats2.push({
          owner: cats[i].owner,
          id: cats[i].id,
          name: cats[i].name,
          type: cats[i].type,
          weight: cats[i].weight,
          eyeColor: cats[i].eyeColor,
          self: cats[i].self,
          preys: preylist,
        });
        preylist = [];
      }
    }
    const q2 = datastore.createQuery(CAT).filter('owner', '=', owner);
    const count = await datastore.runQuery(q2);
    return {data: cats2, count: count[0].length};
}

async function get_cats_unprotected(){
  const q = datastore.createQuery(CAT);
  const entities = await datastore.runQuery(q);
    return entities[0].map(fromDatastore);
}




async function delete_cat(myid, owner){  
    const cat = datastore.key([CAT, parseInt(myid,10)]);
    const mycat = await datastore.get(cat);
  
    if(mycat[0].owner != owner){
        return {"data":"owner"}
    }
    if(mycat[0] == undefined || mycat[0] == null ){
      return {"data":false}
    } 
    if(mycat[0].preys.length > 0){
      for(var i = 0; i < mycat[0].preys.length; i++){
        const prey = datastore.key(["prey", parseInt(mycat[0].preys[i].id,10)]);
        const myprey = await datastore.get(prey)
        if(myprey[0].mostFearedCat != null){
            if (myprey[0].mostFearedCat.id == myid){
                myprey[0].mostFearedCat = null
            }
        await datastore.update(myprey[0])
        }
      }
    }
    datastore.delete(cat);
    return true
}


async function put_cat(id, name, type, weight, eyeColor, owner){
  const cat = datastore.key(["cats", parseInt(id,10)]);
  const mycat = await datastore.get(cat);
  if(mycat[0] == undefined || mycat[0] == null){
    return {"data":false}
  }

  if(mycat[0].owner != owner){
    return {"data":"user"}
 }
  if(!onlyLettersAndSpaces(name)|| !validator.isLength(name, {min:1, max: 26})
    || !validator.isLength(type, {min:1, max: 26}) || !onlyLettersAndSpaces(type)
    || !Number.isInteger(weight) || weight < 1 || weight > 50 || !onlyLettersAndSpaces(eyeColor)|| !validator.isLength(eyeColor, {min:1, max: 26})){
      return {"data": "invalid"}
  }
  const cat_name = datastore.createQuery("cats").filter("name", "=", name);
  const name_results = await datastore.runQuery(cat_name);
  if(name_results[0].length > 0 && name != mycat[0].name){
    return {"data": "name"}
  }
  mycat[0].name = name;
  mycat[0].type = type;
  mycat[0].weight = weight;
  mycat[0].eyeColor = eyeColor;
  mycat[0].owner = owner;
  mycat[0].preys = mycat[0].preys || []
  await datastore.update(mycat[0])
  return { "key": id, "data": mycat[0] };
}


async function patch_cat(id, name, type, weight, eyeColor, owner){
    const cat = datastore.key([CAT, parseInt(id,10)]);
    const mycat = await datastore.get(cat);
    if(mycat[0] == undefined || mycat[0] == null){
        return {"data":false}
    }

    if(mycat[0].owner != owner){
        return {"data":"user"}
    }

    if(name != null && name != mycat[0].name){
    if(!onlyLettersAndSpaces(name)|| !validator.isLength(name, {min:1, max: 26})){
        return {"data": "invalid"}
    }
    const cat_name = datastore.createQuery("cats").filter("name", "=", name);
    const name_results = await datastore.runQuery(cat_name);
    if(name_results[0].length > 0){
        return {"data": "name"}
    }
        mycat[0].name = name
    }
    if(type != null){
        if(!onlyLettersAndSpaces(type)|| !validator.isLength(type, {min:1, max: 26})){
            return {"data": "invalid"}
        }
        mycat[0].type = type
    }
    if(weight != null){
        if(!Number.isInteger(weight) || weight < 1 || weight > 50){
            return {"data": "invalid"}
        }
        mycat[0].weight = weight
    }
    if(eyeColor != null){
        if(!onlyLettersAndSpaces(eyeColor)|| !validator.isLength(eyeColor, {min:1, max: 26})){
            return {"data": "invalid"}
        }
        mycat[0].eyeColor = eyeColor
    }
    if(owner != null){
        mycat[0].owner = owner
    }
    await datastore.update(mycat[0])
    return { "key": id, "data": mycat[0] };
}




async function get_cat(id, owner){
    const cat = datastore.key([CAT, parseInt(id,10)]);
    try {
        const mycat = await datastore.get(cat);
      
        // Check if mycat[0] is undefined or null
        if (!mycat[0]) {
          return {"data": false};
        }

    if(mycat[0].owner != owner){
        return {"data":"owner"}
    }
      for(var i = 0; i < mycat[0].preys.length; i++){
        const prey = datastore.key(["prey", parseInt(mycat[0].preys[i].id,10)]);
        const myprey = await datastore.get(prey)
         mycat[0].preys[i] = {"id": mycat[0].preys[i].id, "self": myprey[0].self, "animal": myprey[0].animal}
      }
    return {"key": cat, "data": mycat};
    } catch (error) {
        console.error(error);
        return {"data": false};
      }
 
}

/* ------------- Begin Prey Model Functions ------------- */
async function post_prey(animal, avgWeight, protein, req) {
    if(!onlyLettersAndSpaces(animal)|| !validator.isLength(animal, {min:1, max: 26})
        || !Number.isInteger(avgWeight) || !validator.isLength(protein, {min:1, max: 26})){
        return {"data": "invalid"}
    }
    const prey_animal = datastore.createQuery("prey").filter("animal", "=", animal);
    const animal_results = await datastore.runQuery(prey_animal);
    if(animal_results[0].length > 0){
        return {"data": "name"}
    }
    const key = datastore.key("prey");
    const new_prey = {"animal": animal, "avgWeight": avgWeight, "protein": protein, "mostFearedCat": null, self: null};
    await datastore.save({"key":key, "data":new_prey});
    await self_prey(key.id, req)
    return key;
}

async function self_prey(id, req){
    const prey = datastore.key(["prey", parseInt(id,10)]);
    const myprey = await datastore.get(prey);
    if(myprey[0] == undefined || myprey[0] == null){
        return {"data":false}
        }
    myprey[0].self = req.protocol + "://" + req.get('host') + req.baseUrl + "/prey/" + id
    await datastore.update(myprey[0])
    return true
}
async function get_prey(limit = 5, offset = 0) {
    const q = datastore.createQuery("prey").limit(limit).offset(offset);
    const entities = await datastore.runQuery(q);
    const prey = entities[0].map(fromDatastore);

    const q2 = datastore.createQuery("prey");
    const count = await datastore.runQuery(q2);

    return { data: prey, count: count[0].length };
  }

async function get_prey_id(id){
    const prey = datastore.key(["prey", parseInt(id,10)]);
    const myprey = await datastore.get(prey);
    if(myprey[0] == undefined || myprey[0] == null ){
      return {"data":false}
    }
    if(myprey[0].mostFearedCat != null){
      const cat = datastore.key([CAT, parseInt(myprey[0].mostFearedCat.id,10)]);
      const mycat = await datastore.get(cat);
      if(mycat[0] == undefined || mycat[0] == null ){
        myprey[0].mostFearedCat = null
        await datastore.update(myprey[0])
      }
        myprey[0].mostFearedCat = {"id": mycat[0].id, "name": mycat[0].name, "self": mycat[0].self}
    }
    return {"key": prey, "data": myprey[0]};
}   


async function delete_prey(id){
    const prey = datastore.key(["prey", parseInt(id,10)]);
  const myprey = await datastore.get(prey);
  if(myprey[0] == undefined || myprey[0] == null){
    return {"data": false }
  }
    if(myprey[0].mostFearedCat != null){
        const cat = datastore.key([CAT, parseInt(myprey[0].mostFearedCat.id,10)]);
        const mycat = await datastore.get(cat);
            if(mycat[0] == undefined || mycat[0] == null){
                return {"data": false }
            }
            for(var i = 0; i < mycat[0].preys.length; i++){
                if(mycat[0].preys[i].id == id){
                    mycat[0].preys.splice(i, 1)
                }
            }
            await datastore.update(mycat[0])
    }
  datastore.delete(prey);
  return true
}

async function put_prey(id, animal, avgWeight, protein){
    const prey = datastore.key(["prey", parseInt(id,10)]);
    const myprey = await datastore.get(prey);
    if(myprey[0] == undefined || myprey[0] == null){
        return {"data":false}
    }
    if(!onlyLettersAndSpaces(animal)|| !validator.isLength(animal, {min:1, max: 26})
        || !Number.isInteger(avgWeight) || !validator.isLength(protein, {min:1, max: 26})){
        return {"data": "invalid"}
    }
    const prey_animal = datastore.createQuery("prey").filter("animal", "=", animal);
    const animal_results = await datastore.runQuery(prey_animal);
    if(animal_results[0].length > 0 && animal != myprey[0].animal){
        return {"data": "name"}
    }
    myprey[0].animal = animal;
    myprey[0].avgWeight = avgWeight;
    myprey[0].protein = protein;
    await datastore.update(myprey[0])
    return { "key": id, "data": myprey[0] };
}

async function patch_prey(id, animal, avgWeight, protein){
    const prey = datastore.key(["prey", parseInt(id,10)]);
    const myprey = await datastore.get(prey);
    if(myprey[0] == undefined || myprey[0] == null){
        return {"data":false}
    }
    if(animal != null && animal != myprey[0].animal){
        if(!onlyLettersAndSpaces(animal)|| !validator.isLength(animal, {min:1, max: 26})){
            return {"data": "invalid"}
        }
        const prey_animal = datastore.createQuery("prey").filter("animal", "=", animal);
        const animal_results = await datastore.runQuery(prey_animal);
        if(animal_results[0].length > 0){
            return {"data": "name"}
        }
        myprey[0].animal = animal
    }
    if(avgWeight != null){
        if(!Number.isInteger(avgWeight)){
            return {"data": "invalid"}
        }
        myprey[0].avgWeight = avgWeight
    }
    if(protein != null){
        if(!validator.isLength(protein, {min:1, max: 26})){
            return {"data": "invalid"}
        }
        myprey[0].protein = protein
    }
    await datastore.update(myprey[0])
    return { "key": id, "data": myprey[0] };
}


/*---------------begin cat and prey functions-----------------*/

async function preywithcats(prey_id, cat_id, owner){
    const prey = datastore.key(["prey", parseInt(prey_id,10)]);
    const myprey = await datastore.get(prey);
    const cat = datastore.key([CAT, parseInt(cat_id,10)]);
    const mycat = await datastore.get(cat);
    if(mycat[0] == undefined || mycat[0] == null || myprey[0] == undefined || myprey[0] == null){
      return {"data":false}
    }
    if(mycat[0].owner != owner){
        return {"data":"owner"}
    }
    if(myprey[0].mostFearedCat == null){
        myprey[0].mostFearedCat = {"id": cat.id, "name": cat.name, "self": cat.self}
    }

    mycat[0].preys.push({"id": prey.id, "self": prey.self, "animal": prey.animal})
    await datastore.update(myprey[0])
    await datastore.update(mycat[0])
    return true 
  }

async function deletepreywithcats(prey_id, cat_id, owner){
    const prey = datastore.key(["prey", parseInt(prey_id,10)]);
    const myprey = await datastore.get(prey);
    const cat = datastore.key([CAT, parseInt(cat_id,10)]);
    const mycat = await datastore.get(cat);

    if(mycat[0].owner != owner){
        return {"data":"owner"}
    }
    if(mycat[0] == undefined || mycat[0] == null || myprey[0] == undefined || myprey[0] == null){
      return {"data":false}
    }
    if(myprey[0].mostFearedCat.id == cat.id){
        myprey[0].mostFearedCat = null
    }
    mycat[0].preys = mycat[0].preys.filter(prey => prey.id != prey_id)
    await datastore.update(myprey[0])
    await datastore.update(mycat[0])
    return true 
}


/* ------------- End Model Functions ------------- */

// Function to get an access token
const getAccessToken = async () => {
    const tokenEndpoint = `https://${DOMAIN}/oauth/token`;
  
    const response = await axios.post(tokenEndpoint, {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: `https://${DOMAIN}/api/v2/`,
      grant_type: 'client_credentials',
      scope: 'read:users',
    });
  
    return response.data.access_token;
  };
  
  // Endpoint to get all users
  app.get('/users', async (req, res) => {
    try {
      const accessToken = await getAccessToken();
  
      const usersEndpoint = `https://${DOMAIN}/api/v2/users`;
  
      const response = await axios.get(usersEndpoint, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
  
      const users = response.data.map((user) => ({
        user_id: user.user_id,
        // Add more fields if needed
      }));
  
      res.json(users);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
/* ------------- Begin Cat Functions ------------- */



app.get('/', function(req, res){
    res.redirect('/cats');
});


app.get('/cats', checkJwt, function (req, res) {
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    if (!req.accepts('application/json')) {
        res.status(406).send({ Error: 'Not Acceptable' });
      }
      const limit = parseInt(req.query.limit) || 5;
      const offset = parseInt(req.query.offset) || 0;
      let next = req.protocol + "://" + req.get('host') + req.baseUrl + "/cats?limit=" + limit + "&offset=" + (limit + offset)
      const cats = get_cats(req.user.sub, limit, offset);
      cats.then((cats) => {
          if(cats.data == false){
              res.status(404).send({Error:"No cats exist for this user"})
          } else {
          if(cats.count > limit + offset){
               next = req.protocol + "://" + req.get('host') + req.baseUrl + "/cats?limit=" + limit + "&offset=" + (limit + offset)  
          }else if(cats.count < limit + offset){
               next = "no more cats"
          }
               res.status(200).json({data: cats.data, Search_results:cats.count, "next": next});
        }
            
      });
});


app.post('/cats', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    let bod = JSON.stringify(req.body)
    bod = JSON.parse(bod)

    post_cat(bod.name, bod.type, bod.weight, bod.eyeColor, req.user.sub, req)
    .then( key => {
        if(key.data == "invalid"){
            res.status(400).send({Error:"The request has invalid data, check the attributes again"})
        } else if(key.data == "name"){     
            res.status(403).send({Error:"Please enter a unique name"})
        } else{
            res.status(201).send({ "id": key.id, "name": bod.name, "type": bod.type,} );
        }
    } );
});


app.patch('/cats/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
  if(req.get('content-type') !== 'application/json'){
    res.status(415).send('Server only accepts application/json data.')
  } else {
    const cat = patch_cat(req.params.id, req.body.name, req.body.type, req.body.weight, req.body.eyeColor, req.user.sub)
    cat.then(cat => {
      if(cat.data != false && cat.data != "invalid" && cat.data != "name" && cat.data != "user"){
        res.status(201).send({ "id": req.params.id, "name": cat.data.name, "type": cat.data.type,
      "weight": cat.data.weight, "eyeColor": cat.data.eyeColor, "self": cat.data.self})
      } else if(cat.data == "invalid"){
        res.status(400).send({Error:"The request has invalid data, check the attributes again"})
      }else if(cat.data == "name"){
        res.status(403).send({Error:"Please enter a unique name"})
      } else if (cat.data == "user"){
        res.status(403).send({Error:"You do not have access to this cat"})
      }else {
      res.status(404).send({Error:"No cat with this cat_id exists"})
    }})
  }
})


app.put('/cats/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
  if(req.get('content-type') !== 'application/json'){
    res.status(415).send('Server only accepts application/json data.')
  }
  if(!req.body.name || !req.body.type || !req.body.weight || !req.body.eyeColor){
    res.status(400).send({Error:"The request object is missing at least one of the required attributes"})
  } else {
    if(req.params.id != req.body.id){
      console.log("you cannot change the id, update will go through without changing id")
    }
    
    const cat = put_cat(req.params.id, req.body.name, req.body.type, req.body.weight, req.body.eyeColor, req.user.sub)
    cat.then(cat => {
      if(cat.data != false && cat.data != "invalid" && cat.data != "name" && cat.data != "user"){
        res.status(201).json({"id": cat.key.id, "name": cat.data.name, "type": cat.data.type,
        "weight": cat.data.weight, "eyeColor": cat.data.eyeColor, "self": cat.data.self});
      } else if(cat.data == "invalid"){
        res.status(400).send({Error:"The request has invalid data, check the attributes again"})
      }else if(cat.data == "name"){
        res.status(403).send({Error:"Please enter a unique name"})
      } else if (cat.data == "user"){
        res.status(403).send({Error:"You do not have access to this cat"})
      } else {
      res.status(404).send({Error:"No cat with this cat_id exists"})
  }})
  }
})


app.delete('/cats/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    const cat = delete_cat(req.params.id, req.user.sub)
    cat.then(cat => {
        if(cat.data != false && cat.data != "owner"){
            res.status(204).send().end()
        } else if (cat.data == "owner") {
            res.status(403).send({Error:"You do not have access to this cat"})
        } else {
            res.status(404).send({Error:"No cat with this cat_id exists"})
        }
    })
});


app.get('/cats/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    const cat = get_cat(req.params.id, req.user.sub)
    cat.then( (cat) => {
        const accepts = req.accepts(['application/json'])
      if(!accepts){
          res.status(406).send({Error:"Not Acceptable"});
      } else if(accepts == 'application/json'){
        if(cat.data != false && cat.data != "owner"){
            res.status(200).json(cat.data);
        } else if(cat.data == "owner"){
            res.status(403).send({Error:"You do not have access to this cat"})
        } else if(cat.data == false){
            res.status(404).send({Error:"No cat with this cat_id exists"})
        }
        }
    });
});

/* ------------- End Cat Functions ------------- */
/* ------------- Begin Prey Functions ------------- */

app.post('/prey', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    let bod = JSON.stringify(req.body)
    bod = JSON.parse(bod)
    if(!bod.animal || !bod.avgWeight || !bod.protein){
        res.status(400).send({Error:"The request object is missing at least one of the required attributes"})
    }
    const prey = post_prey(bod.animal, bod.avgWeight, bod.protein, req)
    prey.then( key => {
        if(key.data == "invalid"){
            res.status(400).send({Error:"The request has invalid data, check the attributes again"})
        } else if(key.data == "name"){
            res.status(403).send({Error:"Please enter a unique animal"})
        } else{
        res.status(201).send({ "id": key.id, "animal": bod.animal } );
        }
    } );
}
);

app.get('/prey', checkJwt, function(req, res) {
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    if (!req.accepts('application/json')) {
      res.status(406).send({ Error: 'Not Acceptable' });
    }
  
    // Extract limit and offset from query parameters, default to 10 and 0 respectively
    const limit = parseInt(req.query.limit) || 5;
    const offset = parseInt(req.query.offset) || 0;
    let next = req.protocol + "://" + req.get('host') + req.baseUrl + "/prey?limit=" + limit + "&offset=" + (limit + offset);
  
    const prey = get_prey(limit, offset);
    prey.then((prey) => {
      if (prey.data == false) {
        res.status(404).send({ Error: "No prey exist" });
      } else if (prey.count > limit + offset) {
        next = req.protocol + "://" + req.get('host') + req.baseUrl + "/prey?limit=" + limit + "&offset=" + (limit + offset);
      } else if (prey.count < limit + offset) {
        next = "no more prey";
      }
      res.status(200).json({ data: prey.data, Search_results: prey.count, "next": next });
    });
  });

app.get('/prey/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    if(!req.accepts('application/json')){
        res.status(406).send({Error:"Not Acceptable"});
    }
    const prey = get_prey_id(req.params.id)
    prey.then( (prey) => {
        const accepts = req.accepts(['application/json'])
        if(!accepts){
            res.status(406).send({Error:"Not Acceptable"});
        } else if(accepts == 'application/json'){
          if(prey.data != false){
              res.status(200).json(prey.data);
          } else {
              res.status(404).send({Error:"No prey with this prey_id exists"})
          }
          }
    });
});

app.delete('/prey/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    const prey = delete_prey(req.params.id)
    prey.then(prey => {
        if(prey.data != false){
            res.status(204).send().end()
        } else {
            res.status(404).send({Error:"No prey with this prey_id exists"})
        }
    })
});

app.put('/prey/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
      }
      if(!req.body.animal || !req.body.avgWeight || !req.body.protein){
        res.status(400).send({Error:"The request object is missing at least one of the required attributes"})
      } else {
        if(req.params.id != req.body.id){
          console.log("you cannot change the id, update will go through without changing id")
        }
        const prey = put_prey(req.params.id, req.body.animal, req.body.avgWeight, req.body.protein)
        prey.then(prey => {
          if(prey.data != false){
            res.status(201).json({"id": req.params.id, "animal": prey.data.animal, "avgWeight": prey.data.avgWeight,
            "protein": prey.data.protein, "self": prey.data.self});
          } else {
          res.status(404).send({Error:"No prey with this prey_id exists"})
      }})
      }
});

app.patch('/prey/:id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
      } else {
        const prey = patch_prey(req.params.id, req.body.animal, req.body.avgWeight, req.body.protein)
        prey.then(prey => {
          if(prey.data != false){
            res.status(201).json({"id": req.params.id, "animal": prey.data.animal, "avgWeight": prey.data.avgWeight,
            "protein": prey.data.protein, "self": prey.data.self});
          } else {
          res.status(404).send({Error:"No prey with this prey_id exists"})
      }})
      }
});

/*---------------begin cat and prey functions-----------------*/

app.put('/cats/:cat_id/prey/:prey_id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in to add a most feared prey and have a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    const addprey = preywithcats(req.params.prey_id, req.params.cat_id, req.user.sub)
    addprey.then(addprey => {
     if(addprey.data != false && addprey.data != "full"){res.status(204).send().end()
    } else if(addprey.data != false){
      res.status(403).send({Error:"You do not have access to this cat"})
    } else {
      res.status(404).send({Error:"The specified cat and/or prey does not exist"})
    }
    })
});

app.delete('/cats/:cat_id/prey/:prey_id', checkJwt, function(req, res){
    if(!req.user.sub){
        res.status(401).send({Error:"You must be logged in with a jwt as the bearer token, you can do this by logging in and then putting the access token in the jwt variables"})
    }
    const deleteprey = deletepreywithcats(req.params.prey_id, req.params.cat_id, req.user.sub)
    deleteprey.then(deleteprey => {
     if(deleteprey.data != false && deleteprey.data != "owner"){
        res.status(204).send().end()
    } else if (deleteprey.data == false) {
      res.status(404).send({Error:"The specified cat and/or prey does not exist"})
    } else{
        res.status(403).send({Error:"You do not have access to this cat"})
    }
    })
});

// User functions//

app.get('/unsecure', function(req, res){
    if(!req.accepts('application/json')){
        res.status(406).send({Error:"Not Acceptable"});
    }
    const cats = get_cats_unprotected()
  .then( (cats) => {
        res.status(200).json(cats);
    });
});

app.get('/users', function(req, res){
    if(!req.accepts('application/json')){
        res.status(406).send({Error:"Not Acceptable"});
    }
  const users = get_users()
  users.then( (users) => {
      res.status(200).json(users);
  });
});

/* ------------- End Controller Functions ------------- */

app.use('/cats', router);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});