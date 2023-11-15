/***************************************************************************************
 *    Title: <Firebase authentication for Asp.net core MVC>
 *    Author: <Arno Waegemans>
 *    Date Published: <17 February 2021>
 *    Date Retrieved: <15 August 2023>
 *    Code version: <1.0.0>
 *    Availability: <https://arno-waegemans.medium.com/firebase-authentication-for-asp-net-core-mvc-defd6135c632>
 *
 ***************************************************************************************/

using FirebaseAuthentication.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
// Firebase.Auth
using Firebase.Auth;
using Microsoft.AspNetCore.Http;

namespace FirebaseAuthentication.Controllers
{
    public class HomeController : Controller
    {
        FirebaseAuthProvider auth;

        public HomeController()
        {
            // Initialize the FirebaseAuthProvider with your Firebase API Key
            auth = new FirebaseAuthProvider(new FirebaseConfig("your_firebase_Web_API_Key"));
        }

        public IActionResult Index()
        {
            // Check if the user is authenticated by verifying the session token
            var token = HttpContext.Session.GetString("_UserToken");
            if (!string.IsNullOrEmpty(token))
            {
                // Retrieve the email from the session
                ViewBag.Email = HttpContext.Session.GetString("UserEmail");
                return View();
            }
            else
            {
                // User is not authenticated, redirect to SignIn page
                return RedirectToAction("SignIn");
            }
        }



        public IActionResult Register()
        {
            // Display the registration form
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(UserModel userModel)
        {
            try
            {
                // Create a new user with the provided email and password
                await auth.CreateUserWithEmailAndPasswordAsync(userModel.Email, userModel.Password);

                // Log in the new user
                var fbAuthLink = await auth.SignInWithEmailAndPasswordAsync(userModel.Email, userModel.Password);
                string token = fbAuthLink.FirebaseToken;

                if (!string.IsNullOrEmpty(token))
                {
                    // Save the Firebase token in a session variable
                    HttpContext.Session.SetString("_UserToken", token);

                    // Inside the Register action method
                    ViewBag.Email = userModel.Email;
                    HttpContext.Session.SetString("UserEmail", userModel.Email); // Store email in session
                    // Redirect to the Index page
                    return RedirectToAction("Index");
                }
                else
                {
                    // Handle the case where authentication failed
                    return View();
                }
            }
            catch (Exception ex)
            {
                // Handle any exceptions that occur during registration
                ViewBag.Error = ex.Message;
                return View();
            }
        }

        public IActionResult SignIn()
        {
            // Display the sign-in form
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignIn(UserModel userModel)
        {
            try
            {
                // Log in the user with the provided email and password
                var fbAuthLink = await auth.SignInWithEmailAndPasswordAsync(userModel.Email, userModel.Password);
                string token = fbAuthLink.FirebaseToken;

                if (!string.IsNullOrEmpty(token))
                {
                    // Save the Firebase token in a session variable
                    HttpContext.Session.SetString("_UserToken", token);

                    // Inside the SignIn action method
                    ViewBag.Email = userModel.Email;
                    HttpContext.Session.SetString("UserEmail", userModel.Email); // Store email in session
                    // Redirect to the Index page
                    return RedirectToAction("Index");
                }
                else
                {
                    // Handle the case where authentication failed
                    return View();
                }
            }
            catch (Exception ex)
            {
                // Handle any exceptions that occur during sign-in
                ViewBag.Error = ex.Message;
                return View();
            }
        }

        public IActionResult LogOut()
        {
            // Remove the user's session token to log them out
            HttpContext.Session.Remove("_UserToken");
            return RedirectToAction("SignIn");
        }
    }
}
