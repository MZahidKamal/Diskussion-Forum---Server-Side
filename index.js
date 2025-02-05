/* ALL NECESSARY IMPORTS ---------------------------------------------------------------------------------------------*/

const express = require('express');                          //Default from Express.js
const cors = require('cors');                      //From CORS Middleware, but positioned here for better reliability and instructed in the document.
const app = express();                                             //Default from Express.js

require('dotenv').config();                                                    //Default from dotenv package.
// console.log(process.env);                                                   //Remove this after you've confirmed it is working.

const port = process.env.PORT || 3000;                            //Default from Express.js but .env applied, therefore positioned after dotenv import.
// console.log(port);

const jwt = require('jsonwebtoken');                                       //Default from JSON Web Token.

const cookieParser = require('cookie-parser');      //Default from cookie-parser package.




/* EMAIL SENDING CONFIGURATION USING NODEMAILER VIA GMAIL ----------------------------------------------------------- */
const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for port 465, false for other ports
    auth: {
        user: "diskussion.forum@gmail.com",
        pass: process.env.GMAIL_APP_PASSWORD,
    },
});

// async..await is not allowed in global scope, must use a wrapper
const sendConfirmationEmailToUser = async (targetEmail, emailSubject, emailBody) => {
    const info = await transporter.sendMail({
        from: 'diskussion.forum@gmail.com',
        to: targetEmail,
        subject: emailSubject,
        html: emailBody
    });
    console.log("Message sent: %s", info.messageId);
}




/* ALL NECESSARY MIDDLEWARES -----------------------------------------------------------------------------------------*/

/* It enables Cross-Origin Resource Sharing (CORS), allowing your server to handle requests from different allowed origins or domains securely.
Credentials: true allows sending and receiving credentials (like cookies or authorization headers) with cross-origin requests.
Methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] specifies which HTTP methods are allowed for cross-origin requests. */
app.use(cors({
    origin: [
        'http://localhost:5173',
        'https://diskussion-forum-phb10-m12a12.netlify.app',
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
}))

/* It helps to parse incoming JSON payloads from the client (e.g., a POST or PUT request with a JSON body) into a JavaScript object, accessible via req.body. */
app.use(express.json());

/* Parses incoming requests with URL-encoded payloads, typically used when data is sent from HTML forms.
Setting extended: true enables parsing of nested objects, allowing for more complex form data structures. */
app.use(express.urlencoded({extended: true}))

/* It allows the server to parse and handle cookies sent by the client in HTTP requests.
After using cookieParser(), you can access cookies through req.cookies (for normal cookies) and req.signedCookies (for signed cookies) in your routes. */
app.use(cookieParser());





// Custom middleware for JWT verification.
const verifyJWT = (req, res, next) => {
    const email = req?.body?.email;
    const token = req?.cookies?.token;
    // console.log({email, token});
    if (!token) {
        return res.status(401).send({ message: "No token provided, authorization denied!" });
    }
    // Verify the JWT
    jwt.verify(token, process.env.ACCESS_JWT_SECRET, (error, decoded) => {
        if (error) {
            return res.status(402).send({ message: "Invalid or expired token!" });
        }
        req.decoded_email = decoded?.data;
        next(); // Call the next middleware.
    });
};





/* MONGODB CONNECTIONS AND APIS --------------------------------------------------------------------------------------*/

const {MongoClient, ServerApiVersion, ObjectId} = require('mongodb');

/* The URI points to a specific MongoDB cluster and includes options for retrying writes and setting the write concern. */
const uri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@cluster0.ktxyk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`; //From MongoDB Connection String

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

console.log('Current selected Domain: ', process.env.NODE_ENVIRONMENT === 'production' ? 'diskussion-forum-phb10-m12a12.netlify.app' : 'localhost');

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();
        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
        const database = client.db("diskussionForumSystemDB");










        /*====================================== AUTH RELATED APIs ===================================================*/

        app.post('/generate_jwt_and_get_token', async (req, res) => {
            const {email} = req.body;

            //Generating JSON Web Token.
            const token = jwt.sign({data: email}, process.env.ACCESS_JWT_SECRET, {expiresIn: '1h'});
            // console.log(token)

            //Setting JWT, at the client side, in the HTTP only cookie.
            res.cookie('token', token, {
                httpOnly: true,                                                                                                             //Cookies access restricted from client side.
                secure: process.env.NODE_ENVIRONMENT === 'production',                                                                      //Set false while in dev environment, and true while in production.
                sameSite: process.env.NODE_ENVIRONMENT === 'production' ? 'none' : 'Lax',                                                   //Protection from CSRF. None or lax supports most cross-origin use cases.
                maxAge: 3600000,                                                                                                            //Token validity in millisecond. Setting this to cookies.
            }).status(201).send({token, success: true, message: "Login Successful, JWT stored in Cookie!"});
        })


        app.post('/logout_and_clear_jwt', (req, res) => {
            // Clearing the HTTP-only cookie by setting maxAge to 0.
            res.clearCookie('token', {
                httpOnly: true,                                                                                                             //Cookies access restricted from client side.
                secure: process.env.NODE_ENVIRONMENT === 'production',                                                                      //Set false while in dev environment, and true while in production.
                sameSite: process.env.NODE_ENVIRONMENT === 'production' ? 'none' : 'Lax',                                                   //Protection from CSRF. None or lax supports most cross-origin use cases.
                maxAge: 0,                                                                                                                  //Token validity in millisecond. Setting this to cookies.
            }).status(200).send({success: true, message: "Logout successful, cookie cleared!"});
        });










        /*====================================== USERS COLLECTION ====================================================*/

        /* CREATING (IF NOT PRESENT) / CONNECTING THE COLLECTION NAMED "userCollection" AND ACCESS IT */
        const userCollection = database.collection("userCollection");


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.post('/users/add_new_user', async (req, res) => {
            try {
                const {newUser} = req.body;
                const result = await userCollection.insertOne(newUser);

                //Sending confirmation email to the user.
                if (result?.insertedId) {
                    const emailBody = `
                    <p>Hello, ${newUser?.displayName}</p>
                    <p>Your <strong>Diskussion Forum</strong> account is activated.</p>
                `;
                    sendConfirmationEmailToUser(
                        newUser?.email,
                        "Diskussion Forum account",
                        emailBody
                    ).then();
                }


                res.status(201).send(result);
            } catch (error) {
                res.status(500).send({ message: "Internal Server Error" });
            }
        });


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.post('/users/get_user_by_email', async (req, res) => {
            const { email } = req.body;
            const query = { email: email };
            const result = await userCollection.findOne(query);
            res.status(200).send(result);
        })


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.post('/users/find_availability_by_email', async (req, res) => {
            const { email } = req.body;
            const query = { email: email };
            const result = await userCollection.findOne(query);
            if (result) {
                res.status(200).json({ exists: true, message: 'Email found in the database.' });
            } else {
                res.status(200).json({ exists: false, message: 'Email not found.' });
            }
        });


        /* THIS USER UPDATE IS SYNCED WITH FIREBASE & MONGODB */
        app.patch('/users/update_existing_user', verifyJWT, async (req, res) => {
            const { email, displayName, photoURL } = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (email !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const query = { email: email };
            const update = { $set: { displayName: displayName, photoURL: photoURL } };
            const result = await userCollection.updateOne(query, update);
            const updatedUser = await userCollection.findOne(query);
            res.status(200).send({result, updatedUser});
        });


        /*app.get('/users/get_all_users_roll_sorted', async (req, res) => {
            const queryPending = { role: 'pending' };
            const pendingUsers = await userCollection.find(queryPending).toArray();
            const queryAdmin = { role: 'admin' };
            const adminUsers = await userCollection.find(queryAdmin).toArray();
            const queryUser = { role: 'user' };
            const userUsers = await userCollection.find(queryUser).toArray();
            const allSortedUsers = [...pendingUsers, ...adminUsers, ...userUsers];
            res.status(200).send(allSortedUsers);
        })*/
        app.post('/users/get_all_users_roll_sorted', verifyJWT, async (req, res) => {
            const {userEmail} = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            // console.log(userEmail);
            try {
                const sortedUsers = await userCollection.aggregate([
                    {
                        $addFields: {
                            roleOrder: {
                                $switch: {
                                    branches: [
                                        { case: { $eq: ["$role", "pending"] }, then: 1 },
                                        { case: { $eq: ["$role", "admin"] }, then: 2 },
                                        { case: { $eq: ["$role", "user"] }, then: 3 },
                                    ],
                                    default: 4
                                }
                            }
                        }
                    },
                    { $sort: { roleOrder: 1 } },
                    { $project: { roleOrder: 0 } } // Exclude the temporary roleOrder field
                ]).toArray();

                res.status(200).send(sortedUsers);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "An error occurred while fetching users." });
            }
        });


        /* THIS USER UPDATE IS SYNCED WITH MONGODB ONLY */
        app.patch('/users/change_user_role', verifyJWT, async (req, res) => {
            const { adminEmail, userId, updatedUserRole } = req.body;
            // console.log(adminEmail, userId, updatedUserRole)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (adminEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const userQuery = { _id: new ObjectId(userId) };
            const update = { $set: { role: updatedUserRole } };
            const options = { upsert: false };
            const result = await userCollection.updateOne(userQuery, update, options);
            res.status(200).send(result);
        });










        /*====================================== POSTS COLLECTION ====================================================*/

        /* CREATING (IF NOT PRESENT) / CONNECTING THE COLLECTION NAMED "postsCollection" AND ACCESS IT */
        const postsCollection = database.collection("postsCollection");


        app.post('/posts/add_new_post', verifyJWT, async (req, res) => {
            const {userEmail, newPostObj} = req.body;
            // console.log(newPostObj)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const result = await postsCollection.insertOne(newPostObj);

            //Saving the post id in the user data.
            const postId = result?.insertedId.toString();
            const userFilter = { email: userEmail };
            const userUpdate = { $push: { createdPosts: postId } };
            const options = { upsert: false, returnDocument: 'after' };
            const userResult = await userCollection.findOneAndUpdate(userFilter, userUpdate, options);

            //Sending confirmation email to the user.
            if (userResult) {
                const emailBody = `
                    <p>Hello, ${userEmail}</p>
                    <p>You have created a new post titled: <strong>${newPostObj?.title}</strong>.</p>
                `;
                sendConfirmationEmailToUser(
                    userEmail,
                    "New Post Created",
                    emailBody
                ).then();
            }

            res.status(201).send(result);
        });


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.get('/posts/get_all_posts', async (req, res) => {
            const cursor = postsCollection.find();
            const results = await cursor.toArray();
            res.status(200).send(results);
        })


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.get('/posts/get_all_filtered_posts', async (req, res) => {

            const {selected_tag, selected_category, posts_per_page, current_page} = req.headers;
            //*** How the data has been sent and how the data is being received require keen observation.
            // console.log(selected_tag, selected_category, posts_per_page, current_page);

            const postsPerPageN = Number(posts_per_page);
            const currentPageN = Number(current_page);
            // console.log(selected_tag, selected_category, postsPerPageN, currentPageN);

            let postQuery = {};
            if (selected_tag) postQuery = { tagIds : { $in: [selected_tag] } };
            if (selected_category) postQuery = { categoryIds : { $in: [selected_category] } };

            // Count the total documents matching the query
            const totalDocuments = await postsCollection.countDocuments(postQuery);

            const cursor = postsCollection.find(postQuery)
                .sort({ publishedOn: -1 })
                .skip((currentPageN-1) * postsPerPageN)
                .limit(postsPerPageN);
            const results = await cursor.toArray();
            res.status(200).send({totalDocuments, results});
        })


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.post('/posts/get_a_post_by_id', async (req, res) => {
            const { userId, postId } = req.body;
            //console.log(userId, postId)

            const postQuery = { _id: new ObjectId(postId) };

            // Fetch the post object
            const result = await postsCollection.findOne(postQuery);

            if (result) {

                //Adding view count into the post
                const postFilter = { _id: new ObjectId(postId) };
                const postUpdate = {
                    $inc: { 'stats.viewCounts': 1 }
                };
                const postOptions = { upsert: false, returnDocument: 'after' };
                const postResult = await postsCollection.findOneAndUpdate(postFilter, postUpdate, postOptions);

                // Fetch the author object based on authorId
                const authorQuery = { _id: new ObjectId(result.authorId) };
                const authorObj = await userCollection.findOne(authorQuery);
                // Attach the author to the post object
                result.author = authorObj;
                // Remove the authorId field
                delete result.authorId;

                // Fetch the category objects based on categoryIds
                const categoryQuery = { _id: { $in: result.categoryIds.map(id => new ObjectId(id)) } };
                const categoriesArray = await categoriesCollection.find(categoryQuery).toArray();
                // Attach the categories to the post object
                result.categories = categoriesArray;
                // Remove the categoryIds field
                delete result.categoryIds;

                // Fetch the tag objects based on tagIds
                const tagQuery = { _id: { $in: result.tagIds.map(id => new ObjectId(id)) } };
                const tagsArray = await tagsCollection.find(tagQuery).toArray();
                // Attach the tags to the post object
                result.tags = tagsArray;
                // Remove the tagIds field
                delete result.tagIds;

                // Fetch the comment objects based on commentIds
                const commentQuery = { _id: { $in: result.commentIds.map(id => new ObjectId(id)) } };
                const commentsArray = await commentsCollection.find(commentQuery).toArray();

                // Attach the comments to the post object
                result.comments = commentsArray;
                // Remove the commentIds field
                delete result.commentIds;

                // console.log(result);
                res.status(200).send(result);
            }
            else {
                res.status(404).send({ message: 'Post not found' });
            }
        });


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.get('/posts/get_a_post_by_id', async (req, res) => {
            const { 'user-id': userId, 'post-id': postId } = req.headers;
            // console.log(userId, postId)

            const postQuery = { _id: new ObjectId(postId) };

            // Fetch the post object
            const result = await postsCollection.findOne(postQuery);

            if (result) {

                //Adding view count into the post
                const postFilter = { _id: new ObjectId(postId) };
                const postUpdate = {
                    $inc: { 'stats.viewCounts': 1 }
                };
                const postOptions = { upsert: false, returnDocument: 'after' };
                const postResult = await postsCollection.findOneAndUpdate(postFilter, postUpdate, postOptions);

                // Fetch the author object based on authorId
                const authorQuery = { _id: new ObjectId(result.authorId) };
                const authorObj = await userCollection.findOne(authorQuery);
                // Attach the author to the post object
                result.author = authorObj;
                // Remove the authorId field
                delete result.authorId;

                // Fetch the category objects based on categoryIds
                const categoryQuery = { _id: { $in: result.categoryIds.map(id => new ObjectId(id)) } };
                const categoriesArray = await categoriesCollection.find(categoryQuery).toArray();
                // Attach the categories to the post object
                result.categories = categoriesArray;
                // Remove the categoryIds field
                delete result.categoryIds;

                // Fetch the tag objects based on tagIds
                const tagQuery = { _id: { $in: result.tagIds.map(id => new ObjectId(id)) } };
                const tagsArray = await tagsCollection.find(tagQuery).toArray();
                // Attach the tags to the post object
                result.tags = tagsArray;
                // Remove the tagIds field
                delete result.tagIds;

                // Fetch the comment objects based on commentIds
                const commentQuery = { _id: { $in: result.commentIds.map(id => new ObjectId(id)) } };
                const commentsArray = await commentsCollection.find(commentQuery).toArray();

                // Attach the comments to the post object
                result.comments = commentsArray;
                // Remove the commentIds field
                delete result.commentIds;

                // console.log(result);
                res.status(200).send(result);
            }
            else {
                res.status(404).send({ message: 'Post not found' });
            }
        });


        app.post('/posts/get_all_my_posts', verifyJWT, async (req, res) => {
            const { userId, userEmail } = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            // Fetch the post user
            const userQuery = { _id: new ObjectId(userId) };
            const userResult = await userCollection.findOne(userQuery);

            if (!userResult) {
                return res.status(404).send({ message: 'User not found' });
            }

            // Fetch the post objects based on userId
            const myPostsQuery = { _id: { $in: userResult.createdPosts.map(id => new ObjectId(id)) } };
            const myPostsArray = await postsCollection.find(myPostsQuery).toArray();
            return res.status(200).send(myPostsArray);
        })


        app.patch('/posts/update_a_post', verifyJWT, async (req, res) => {
            const { userEmail, updatedPostObj } = req.body;
            // console.log(updatedPostObj)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            // Extract the necessary fields for the update
            const { _id, title, description, categoryIds, tagIds } = updatedPostObj;

            const filter = { _id: new ObjectId(_id) };

            const existingPost = await postsCollection.findOne(filter);
            if (!existingPost) {
                return res.status(404).send({ message: 'Post not found' });
            }

            // Create the update object only with the fields that need updating
            const update = {
                $set: {
                    title,
                    description,
                    categoryIds,
                    tagIds,
                },
            };
            const options = { upsert: false };

            const result = await postsCollection.updateOne(filter, update, options);
            res.status(200).send(result);
        })


        /*app.patch('/posts/vote_a_post', verifyJWT, async (req, res) => {
            const { userEmail, userId, postId, vote } = req.body;
            console.log(userEmail, userId, postId, vote)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const postFilter = { _id: new ObjectId(postId) };
            let postUpdate = null;
            if (vote === 1) postUpdate = {$inc: { 'stats.upVoteCounts': 1 }};
            else if (vote === -1) postUpdate = {$inc: { 'stats.downVoteCounts': 1 }};
            const postOptions = { upsert: false, returnDocument: 'after' };
            const postResult = await postsCollection.findOneAndUpdate(postFilter, postUpdate, postOptions);

            const userFilter = { _id: new ObjectId(userId) };
            let userUpdate = null;
            if (vote === 1) userUpdate = {$push: { 'upVotedPosts': postId }};
            else if (vote === -1) userUpdate = {$push: { 'downVotedPosts': postId }};
            const userOptions = { upsert: false, returnDocument: 'after' };
            const userResult = await userCollection.findOneAndUpdate(userFilter, userUpdate, userOptions);
            res.status(200).send({message: 'Vote processed successfully!'});

        })*/
        app.patch('/posts/vote_a_post', verifyJWT, async (req, res) => {
            const { userEmail, userId, postId, vote } = req.body;
            //console.log(userEmail, userId, postId, vote);

            const { decoded_email } = req;
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const postFilter = { _id: new ObjectId(postId) };
            const userFilter = { _id: new ObjectId(userId) };

            // Fetch user data
            const user = await userCollection.findOne(userFilter);
            if (!user) return res.status(404).send({ message: "User not found!" });

            // Initialize updates
            let postUpdate = {};
            let userUpdate = {};

            // Check if user has already upvoted or downvoted
            const hasUpvoted = user.upVotedPosts?.includes(postId);
            const hasDownvoted = user.downVotedPosts?.includes(postId);

            if (vote === 1) { // Upvote
                if (hasDownvoted) {
                    // Remove downvote and add upvote
                    postUpdate = {
                        $inc: { 'stats.upVoteCounts': 1, 'stats.downVoteCounts': -1 }
                    };
                    userUpdate = {
                        $pull: { downVotedPosts: postId },
                        $push: { upVotedPosts: postId }
                    };
                } else if (!hasUpvoted) {
                    // Add upvote only
                    postUpdate = { $inc: { 'stats.upVoteCounts': 1 } };
                    userUpdate = { $push: { upVotedPosts: postId } };
                }
            } else if (vote === -1) { // Downvote
                if (hasUpvoted) {
                    // Remove upvote and add downvote
                    postUpdate = {
                        $inc: { 'stats.upVoteCounts': -1, 'stats.downVoteCounts': 1 }
                    };
                    userUpdate = {
                        $pull: { upVotedPosts: postId },
                        $push: { downVotedPosts: postId }
                    };
                } else if (!hasDownvoted) {
                    // Add downvote only
                    postUpdate = { $inc: { 'stats.downVoteCounts': 1 } };
                    userUpdate = { $push: { downVotedPosts: postId } };
                }
            }

            // Update post and user
            const postOptions = { upsert: false, returnDocument: 'after' };
            const userOptions = { upsert: false, returnDocument: 'after' };

            const postResult = await postsCollection.findOneAndUpdate(postFilter, postUpdate, postOptions);
            const userResult = await userCollection.findOneAndUpdate(userFilter, userUpdate, userOptions);

            res.status(200).send({
                message: 'Vote processed successfully!',
                postResult,
                userResult
            });
        });



        app.post('/posts/delete_one_of_my_post', verifyJWT, async (req, res) => {
            const { userEmail, postId } = req.body;
            // console.log(userEmail, postId);

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const postID = new ObjectId(postId);
            const filter = { _id: postID };
            const result = await postsCollection.deleteOne(filter);

            if (result?.deletedCount > 0) {

                const userFilter = { email: userEmail };
                const userUpdate = { $pull: { createdPosts: postId } };
                const options = { upsert: false, returnDocument: 'after' };
                const userResult = await userCollection.findOneAndUpdate(userFilter, userUpdate, options);

                res.status(200).send({ message: 'Post deleted successfully!' });
            }
            else {
                res.status(404).send({ message: 'Post not found. Please try again!' });
            }
        })










        /*====================================== CATEGORIES COLLECTION ===============================================*/

        /* CREATING (IF NOT PRESENT) / CONNECTING THE COLLECTION NAMED "tagsCollection" AND ACCESS IT */
        const categoriesCollection = database.collection("categoriesCollection");


        app.post('/categories/create_new_categories', verifyJWT, async (req, res) => {
            const { email, categoriesArray } = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (email !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const operations = categoriesArray.map(category => ({
                updateOne: {
                    filter: { name: category },
                    update: { $set: { name: category } },
                    upsert: true // Insert if not exists
                }
            }));
            const result = await categoriesCollection.bulkWrite(operations);
            res.status(201).send({
                message: 'Categories processed successfully!',
                insertedCount: result.upsertedCount,
                matchedCount: result.matchedCount
            });
        });


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.get('/categories/get_all_categories', async (req, res) => {
            const cursor = categoriesCollection.find();
            const results = await cursor.toArray();
            res.status(200).send(results);
        })










        /*====================================== TAGS COLLECTION =====================================================*/

        /* CREATING (IF NOT PRESENT) / CONNECTING THE COLLECTION NAMED "tagsCollection" AND ACCESS IT */
        const tagsCollection = database.collection("tagsCollection");


        app.post('/tags/create_new_tags', verifyJWT, async (req, res) => {
            const { email, tagsArray } = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (email !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            // console.log(tagsArray);
            // const documents = tagsArray.map(tag => ({ name: tag }));
            // const result = await tagsCollection.insertMany(documents);
            // res.status(201).send({ message: 'Tags stored successfully!', insertedCount: result.insertedCount });
            const operations = tagsArray.map(tag => ({
                updateOne: {
                    filter: { name: tag },
                    update: { $set: { name: tag } },
                    upsert: true // Insert if not exists
                }
            }));
            const result = await tagsCollection.bulkWrite(operations);
            res.status(201).send({
                message: 'Tags processed successfully!',
                insertedCount: result.upsertedCount,
                matchedCount: result.matchedCount
            });
        });


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.get('/tags/get_all_tags', async (req, res) => {
            const cursor = tagsCollection.find();
            const results = await cursor.toArray();
            res.status(200).send(results);
        })










        /*====================================== COMMENTS COLLECTION =================================================*/


        /* CREATING (IF NOT PRESENT) / CONNECTING THE COLLECTION NAMED "commentsCollection" AND ACCESS IT */
        const commentsCollection = database.collection("commentsCollection");


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        /*app.get('/comments/get_all_comments', async (req, res) => {
            const cursor = commentsCollection.find();
            const results = await cursor.toArray();
            res.status(200).send(results);
        })*/


        app.post('/comments/get_all_reported_comments', verifyJWT, async (req, res) => {
            const { userEmail } = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const commentQuery1 = { reportAction: { $eq: "Reported" } };
            const reportedComments1 = await commentsCollection.find(commentQuery1).toArray();
            const commentQuery2 = { reportAction: { $eq: "Hide Comment" } };
            const reportedComments2 = await commentsCollection.find(commentQuery2).toArray();
            const commentQuery3 = { reportAction: { $eq: "No Action Needed" } };
            const reportedComments3 = await commentsCollection.find(commentQuery3).toArray();
            const reportedComments = [...reportedComments1, ...reportedComments2, ...reportedComments3];
            res.status(200).send(reportedComments);
        })


        app.post('/comments/add_new_comment', verifyJWT, async (req, res) => {
            const {userEmail, postId, newCommentObj} = req.body;
            // console.log(userEmail, newCommentObj)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const result = await commentsCollection.insertOne(newCommentObj);
            const commentId = result?.insertedId.toString();

            //Saving the comment id in the post data.
            const postFilter = { _id: new ObjectId(postId) };
            const postUpdate = {
                $push: { commentIds: commentId },
                $inc: { 'stats.commentCounts': 1 }
            };
            const postOptions = { upsert: false, returnDocument: 'after' };
            const postResult = await postsCollection.findOneAndUpdate(postFilter, postUpdate, postOptions);

            //Saving the comment id in the user data.
            const userFilter = { email: userEmail };
            const userUpdate = { $push: { createdComments: commentId } };
            const userOptions = { upsert: false, returnDocument: 'after' };
            const userResult = await userCollection.findOneAndUpdate(userFilter, userUpdate, userOptions);

            res.status(201).send(result);
        });


        app.patch('/comments/update_a_comments', verifyJWT, async (req, res) => {
            const { userEmail, updatedCommentObj } = req.body;

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const query = { _id: new ObjectId(updatedCommentObj._id) };
            const {_id, ...fieldsToUpdate} = updatedCommentObj;
            const update = { $set: fieldsToUpdate };
            const result = await commentsCollection.updateOne(query, update);
            res.status(200).send(result);
        })


        app.patch('/comments/update_report_action', verifyJWT, async (req, res) => {
            const { adminEmail, commentId, updatedReportAction } = req.body;
            // console.log(adminEmail, commentId, updatedReportAction)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (adminEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const commentQuery = { _id: new ObjectId(commentId) };
            const update = { $set: { reportAction: updatedReportAction } };
            const options = { upsert: false };
            const result = await commentsCollection.updateOne(commentQuery, update, options);
            res.status(200).send(result);
        });










        /*====================================== ANNOUNCEMENTS COLLECTION =================================================*/


        /* CREATING (IF NOT PRESENT) / CONNECTING THE COLLECTION NAMED "commentsCollection" AND ACCESS IT */
        const announcementsCollection = database.collection("announcementsCollection");


        /* VERIFY JWT MIDDLEWARE WILL NOT WORK HERE, USER MAY UNAVAILABLE */
        app.get('/announcements/get_all_announcements', async (req, res) => {
            const cursor = announcementsCollection.find().sort({ publishDate: -1 });
            const results = await cursor.toArray();
            res.status(200).send(results);
        })


        app.post('/announcements/add_new_announcement', verifyJWT, async (req, res) => {
            const {userEmail, newAnnouncementObj} = req.body;
            // console.log(userEmail, newAnnouncementObj)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const result = await announcementsCollection.insertOne(newAnnouncementObj);

            //Saving the post id in the user data.
            const announcementId = result?.insertedId.toString();
            const userFilter = { email: userEmail };
            const userUpdate = { $push: { createdAnnouncements: announcementId } };
            const options = { upsert: false, returnDocument: 'after' };
            const userResult = await userCollection.findOneAndUpdate(userFilter, userUpdate, options);

            res.status(201).send(result);
        });


        app.patch('/announcements/make_an_announcement_read', verifyJWT, async (req, res) => {
            const { userEmail, userId, announcementId } = req.body;
            // console.log(userEmail, userId, announcementId)

            const { decoded_email } = req;
            // console.log(email, decoded_email);
            if (userEmail !== decoded_email) {
                return res.status(403).send({ message: "Forbidden access, email mismatch!" });
            }

            const announcementFilter = { _id: new ObjectId(announcementId) };
            const announcementUpdate = { $push: { viewedByUserIds: userId } };
            const announcementOptions = { upsert: false, returnDocument: 'after' };
            const announcementResult = await announcementsCollection.findOneAndUpdate(announcementFilter, announcementUpdate, announcementOptions);
            res.status(200).send(announcementResult);
        })





        /*============================================================================================================*/


    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}

run().catch(console.dir);





/* REST CODE OF EXPRESS.JS -------------------------------------------------------------------------------------------*/

/* This defines a route handler for the root URL (/).
When a GET request is made to the root, it sends the response: "Diskussion Forum Server Side is running!". */
app.get('/', (req, res) => {
    res.send('Diskussion Forum Server Side is running!');
})


/* This starts the Express server and listens for incoming connections on the specified port.
It logs a message in the console indicating the app is running and the port it's listening on. */
app.listen(port, () => {
    console.log(`Diskussion Forum app listening on port ${port}`);
})
