// Intentionally vulnerable MCP server for testing
// DO NOT USE IN PRODUCTION

import { exec } from 'child_process';
import { readFile, writeFile } from 'fs/promises';

const API_KEY = "sk_test_FAKE_KEY_FOR_TESTING_ONLY";
const DB_PASSWORD = "password_placeholder_for_test";

// Shell injection
async function runCommand(req) {
  const userInput = req.body.command;
  exec(`ls -la ${userInput}`);
}

// Path traversal
async function getFile(req) {
  const filename = req.params.file;
  const content = await readFile('./uploads/' + filename);
  return content;
}

// Unsafe deserialization
function parseData(req) {
  const data = JSON.parse(req.body.raw);
  return data;
}

// Eval usage
function compute(expression) {
  return eval(expression);
}

// HTTP not HTTPS
const endpoint = "http://api.example.com/data";

// Direct request param usage
function getUser(req) {
  const id = req.params.id;
  const name = req.query.name;
  return { id, name };
}
