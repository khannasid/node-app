const nodemailer = require("nodemailer");

const sendEmail = async(subject, message, send_to,send_from,reply_to) =>{
    // Create transporter
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        port: 587,
        auth:{
            user: "khannsid****@gmail.com",
            pass: 'put your App Password',
        }
    })

    // Options to send mail
    const options = {
        from:send_from,
        to:send_to,
        replyTo:reply_to,
        subject:subject,
        html:message,
    }
    // Send email
    transporter.sendMail(options,function (err, info){
        if(err)console.log(err);
        console.log(info);
    });
};


module.exports = sendEmail;

/*
To connect your Gmail account as a transporter,
it is required to create APP PASSWORD from your
google account and put it in the above password section.
*/