"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'promote_to_case_add_comment_1' block
    promote_to_case_add_comment_1(container=container)

    return

def promote_to_case_add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_add_comment_1() called")

    playbook_input_reason = phantom.collect2(container=container, datapath=["playbook_input:reason"])

    playbook_input_reason_values = [item[0] for item in playbook_input_reason]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Suspicious Email")
    phantom.comment(container=container, comment=playbook_input_reason_values)

    container = phantom.get_container(container.get('id', None))

    prompt_1(container=container)

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The geo data: \n{0}\n\nthe filtered IP(s): {1}\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:geo_list",
        "playbook_input:ip"
    ]

    # responses
    response_types = [
        {
            "prompt": "message:",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "do you want to change the label to splunk?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.1", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_label_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def set_label_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_label_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_label(container=container, label="splunk")

    container = phantom.get_container(container.get('id', None))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]

    output = {
        "msg_for_hud": prompt_1_summary_responses_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return