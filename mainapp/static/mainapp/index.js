const textField = document.getElementById("grid-1");
const btn = document.querySelector("input[type='submit']");
const getCSRFToken = () => {
    return document.querySelector("[name=csrfmiddlewaretoken]")?.value;
};

document.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
    checkbox.addEventListener("change", function () {
        if (this.checked) {
            document.querySelectorAll('input[type="checkbox"]').forEach((other) => {
                if (other !== this) {
                    other.checked = false;
                }
            });
        }
    });
});

const type = () => {
    const checkB = document.querySelector('input[type="checkbox"]:checked');
    if (checkB) {
        console.log("The value of the checkbox is:", checkB.value);
    } else {
        console.log("No checkbox is selected.");
    }
    return checkB.id;
};

const textFieldFunction = () => {
    console.log("Text field value:", textField.value.trim());
    return textField.value.trim();
};

const radioFunction = () => {
    const selectedRadio = document.querySelector(".method:checked");
    return selectedRadio ? selectedRadio.id : null;
};

btn.addEventListener("click", (event) => {
    event.preventDefault();
    const textF = textFieldFunction();
    const radioF = radioFunction();
    const checkB = type();

    if (!textF) {
        console.log("Error: Text field is empty!");
        return;
    }
    if (!radioF) {
        console.log("Error: No encryption type selected!");
        return;
    }

    handleInput(textF, radioF, checkB);
});

const handleInput = async (textF, radioF, type) => {
    const data = {
        encryptionType: radioF,
        message: textF,
        type: type,
    };

    try {
        const res = await fetch("http://127.0.0.1:8000/api", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": getCSRFToken(),
            },
            body: JSON.stringify(data),
        });

        if (!res.ok) {
            throw new Error(`HTTP error! Status: ${res.status}`);
        }

        const jsonData = await res.json();
        console.log("Server Response:", jsonData);
    } catch (error) {
        console.error("Error sending data:", error);
    }
};
