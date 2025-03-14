require('dotenv').config();
const chalk = require('chalk');
const mongoose = require('mongoose');

const keys = require('../config/keys');
const { database } = keys;

// const setupDB = async () => {
//   try {
//     // Connect to MongoDB
//     console.log('connecting......')
//     mongoose.set('useCreateIndex', true);
//     mongoose
//       .connect(database.url, {
//         useNewUrlParser: true,
//         useUnifiedTopology: true,
//         useFindAndModify: false
//       })
//       .then(() =>{
//         console.log(`${chalk.green('✓')} ${chalk.blue('MongoDB Connected!')}`)
//   })
//       .catch(err => console.log(err));
//   } catch (error) {
//     return null;
//   }
// };

const setupDB = async () => {
  try {
    console.log('Connecting to MongoDB...');
    mongoose.set('strictQuery', false);

    await mongoose.connect(database.url, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    console.log(chalk.green('✓ MongoDB Connected!'));
  } catch (error) {
    console.error(chalk.red('✗ MongoDB Connection Error:'), error.message);
  }
};


module.exports = setupDB;
